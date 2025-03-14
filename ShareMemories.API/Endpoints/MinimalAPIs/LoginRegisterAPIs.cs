﻿using Ardalis.GuardClauses;
using FluentValidation;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using System.Text;

namespace ShareMemories.API.Endpoints.MinimalAPIs
{
    public class LoginRegisterAPIs
    {
        private readonly WebApplication app;

        public LoginRegisterAPIs(WebApplication webApp) => app = webApp;

        public void RegisterLoginAPI()
        {
            /*******************************************************************************************************
             * Register a new user (adding FluentValidator to ensure data integrity from client)
             *******************************************************************************************************/
            app.MapPost("/RegisterAsync", async (RegisterUserDto user, IAuthService authService) =>
            {
                IEnumerable<IdentityError> result = await authService.RegisterUserAsync(user);

                if (result.Any())
                {
                    var errors = new StringBuilder();
                    result.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                    return Results.BadRequest(errors.ToString());
                }

                return Results.Ok("Successfully registered, you can now login.");

            }).WithName("RegisterAsync")
              .WithOpenApi(x => new OpenApiOperation(x)
              {
                  Summary = "Register a new user",
                  Description = "Registers a new user within the .Net Roles Identity DB.  Returns a status string for the operation.",
                  Tags = new List<OpenApiTag> { new() { Name = "Login/Register API Library" } }
              })
              .CacheOutput(x => x.Tag("LoginUser")); // invalidate data when new record added, by using tag in Post API
              // .AddEndpointFilter<GenericValidationFilter<LoginUser>>(); // apply fluent validation to DTO model from client and pass back broken rules
              // Password validation done by builder.service.AddIdentity in Programs.cs


            /*******************************************************************************************************
             * Login an already registered user
             *******************************************************************************************************/
            app.MapPost("/LoginAsync", async (LoginUserDto user, IAuthService authService) =>
            {
                var loginResult = await authService.LoginAsync(user);

                if (loginResult.IsLoggedIn)
                {
                    return Results.Ok(loginResult);
                }

                //if (await authService.LoginAsync(user))
                //{
                //    //var tokenString = authService.GenerateTokenString(user);
                //    //return Results.Ok(tokenString);

                //    var loginResult = await authService.Login(user);
                //    if (loginResult.IsLogedIn)
                //    {
                //        return Results.Ok(loginResult);
                //    }
                //}

                return Results.BadRequest("User credentials could not be verified.");
            })
            .WithName("LoginAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Login",
                Description = "Logs in the user and returns a JWT token if successful.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register API Library" } }
            })
            .CacheOutput(x => x.Tag("LoginUser"))
            .AddEndpointFilter<GenericValidationFilter<LoginUserValidator,RegisterUserDto>>(); // apply fluent validation to DTO model from client and pass back broken rules    

            /*******************************************************************************************************
            * Refresh a user's login instance, without having to pass the credentials again
            *******************************************************************************************************/
            app.MapPost("/RefreshTokenAsync", async (RefreshTokenModel refreshModel, IAuthService authService) =>
            {
                // apply guard rules to individual property's - could also use FluentValidator!
                Guard.Against.Empty(refreshModel.JwtToken, nameof(refreshModel.JwtToken), "JWT must not be supplied");
                Guard.Against.Empty(refreshModel.RefreshToken, nameof(refreshModel.RefreshToken), "Refresh token must not be supplied");

                var loginResult = await authService.RefreshTokenAsync(refreshModel);

                if (loginResult.IsLoggedIn)
                {
                    return Results.Ok(loginResult);
                }
                return Results.Unauthorized();
            })
            .WithName("RefreshTokenAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Refresh Token",
                Description = "Using the refresh & JWT token you can request to be logged back in again, without having to supply credentials.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });            

        } // end class
    }
}
