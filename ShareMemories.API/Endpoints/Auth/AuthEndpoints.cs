using Ardalis.GuardClauses;
using Azure;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;
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
            group.MapPost("/LoginAsync", async (LoginUserDto user, IAuthService authService, HttpContext context) =>
            {
                const int REFRESH_TOKEN_EXPIRE_DAYS = 10;
                const int JWT_TOKEN_EXPIRE_MINS = 30;

                var loginResult = await authService.LoginAsync(user);

                if (loginResult.IsLoggedIn)
                {
                    // Set the JWT as a HttpOnly cookie
                    var cookieOptionsJWT = new CookieOptions
                    {
                        HttpOnly = true,
                        IsEssential = true,
                        Secure = true, // Ensures the cookie is sent over HTTPS
                        SameSite = SameSiteMode.Strict, // Helps mitigate CSRF attacks                        
                        //Expires = DateTimeOffset.UtcNow.AddMinutes(JWT_TOKEN_EXPIRE_MINS) // Set expiration                        
                        Expires = DateTimeOffset.UtcNow.AddSeconds(30) // Set expiration                        
                    };
                    
                    // Set the Refresh Token as a HttpOnly cookie
                    var cookieOptionsRefreshJWT = new CookieOptions
                    {
                        HttpOnly = true,
                        IsEssential = true,
                        Secure = true, // Ensures the cookie is sent over HTTPS
                        SameSite = SameSiteMode.Strict, // Helps mitigate CSRF attacks                        
                        //Expires = DateTimeOffset.UtcNow.AddDays(REFRESH_TOKEN_EXPIRE_DAYS) // Set expiration
                        Expires = DateTimeOffset.UtcNow.AddSeconds(30) // Set expiration
                         
                    };

                    // Set the cookie in the response
                    context.Response.Cookies.Append("jwtToken", loginResult.JwtToken, cookieOptionsJWT);
                    context.Response.Cookies.Append("jwtRefreshToken", loginResult.JwtRefreshToken, cookieOptionsRefreshJWT);

                    //return Results.Ok(new { message = "Logged in successfully" });
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
            group.MapPost("/RefreshTokenAsync", async (IAuthService authService, HttpContext context) =>
            {
                // verify cookies exist in request
                if (context.Request.Cookies.ContainsKey("jwtToken") && context.Request.Cookies.ContainsKey("jwtRefreshToken"))
                {
                    // guard that they are not empty
                    Guard.Against.Empty(context.Request.Cookies["jwtToken"], "JWT must not be supplied");
                    Guard.Against.Empty(context.Request.Cookies["jwtRefreshToken"], "Refresh token must not be supplied");
                }
                else throw new ArgumentException("JWT Token cookie must be supplied.");

                var loginResult = await authService.RefreshTokenAsync(context.Request.Cookies["jwtToken"]!, context.Request.Cookies["jwtRefreshToken"]!);

                if (loginResult.IsLoggedIn)
                {
                    //return Results.Ok(loginResult);
                    return Results.Ok("Successfully refreshed JWT Bearer");
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

            /*******************************************************************************************************
            *                           Allow user to logout and delete their JWT Token                            *
            *******************************************************************************************************/
            // Define the logout endpoint
            group.MapPost("/logoutAsync", async (IAuthService authService) =>
            //group.MapPost("/logoutAsync", async (HttpContext context, IAuthService authService) =>
            {
                //// Clear the JWT cookie
                //context.Response.Cookies.Delete("jwtToken");
                //context.Response.Cookies.Delete("jwtRefreshToken");
                
                await authService.LogoutAsync();

                return Results.Ok(new { message = "Logged out successfully" });
            })
            .WithName("Logout")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Logout user",
                Description = "Logout user and delete their cached JWT token.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });
        }
    }
}
