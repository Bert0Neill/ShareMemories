using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using System.Text;

namespace ShareMemories.API.Endpoints.Auth
{
    public static class AuthEndpoints
    {        
        public static void MapAuthEndpoints(this IEndpointRouteBuilder routes)
        {
            var group = routes.MapGroup("auths")
              .WithOpenApi();

            /*******************************************************************************************************
             * Register a new user (adding FluentValidator to ensure data integrity from client)
             *******************************************************************************************************/
            group.MapPost("/RegisterAsync", async (RegisterUserDto user, IAuthService authService) =>
            {
                var result = await authService.RegisterUserAsync(user);

                if (result.IsLoggedIn) return Results.Ok("Successfully registered, you can now login.");                
                else return Results.BadRequest(new { Errors = result.Message });
                
            }).WithName("RegisterAsync")
              .WithOpenApi(x => new OpenApiOperation(x)
              {
                  Summary = "Register a new user",
                  Description = "Registers a new user within the .Net Roles Identity DB. Must have a unique Username & Email to be valid. Returns a boolean status and an error string (if applicable).",
                  Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
              })
              .CacheOutput(x => x.Tag("LoginUser")) // invalidate data when new record added, by using tag in Post API                                                     

            // !!! Password validation done by builder.service.AddIdentity in Programs.cs
            .AddEndpointFilter<GenericValidationFilter<RegisterUserValidator, RegisterUserDto>>(); // apply fluent validation to DTO model from client and pass back broken rules    


            /*******************************************************************************************************
             * Login an already registered user
             *******************************************************************************************************/
            group.MapPost("/LoginAsync", async (LoginUserDto user, IAuthService authService) =>
            {
                var loginResult = await authService.LoginAsync(user);

                if (loginResult.IsLoggedIn)
                {
                    return Results.Ok(loginResult);
                }

                return Results.BadRequest("User credentials could not be verified.");
            })
            .WithName("LoginAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Login",
                Description = "Logs in the user and returns a JWT token if successful.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            })
            .CacheOutput(x => x.Tag("LoginUser"))
            .AddEndpointFilter<GenericValidationFilter<LoginUserValidator, LoginUserDto>>(); // apply fluent validation to DTO model from client and pass back broken rules    

            /*******************************************************************************************************
            * Refresh a user's login instance, without having to pass the credentials again
            *******************************************************************************************************/
            group.MapPost("/RefreshTokenAsync", async (RefreshTokenModel refreshModel, IAuthService authService) =>
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
                Description = "Using refresh & JWT token, you can request to be logged back in again, without having to supply credentials.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

        }
    }
}
