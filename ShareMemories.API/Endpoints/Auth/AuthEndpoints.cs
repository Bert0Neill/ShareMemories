using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Infrastructure.Interfaces;

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
            group.MapPost("/RegisterAsync", async Task<Results<Ok<string>, BadRequest<string>>> (RegisterUserDto user, IAuthService authService) =>
            {
                var result = await authService.RegisterUserAsync(user);

                if (result.IsLoggedIn) return TypedResults.Ok("Successfully registered, you can now login.");
                else return TypedResults.BadRequest(result.Message);

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
                var loginResult = await authService.LoginAsync(user);

                if (loginResult.IsLoggedIn)
                {
                    //CookieOptions cookieOptionsJWT, cookieOptionsRefreshJWT;
                    //GenerateCookieOptions(loginResult, out cookieOptionsJWT, out cookieOptionsRefreshJWT);
                    //// Set the cookie in the response
                    //context.Response.Cookies.Append("jwtToken", loginResult.JwtToken, cookieOptionsJWT);
                    //context.Response.Cookies.Append("jwtRefreshToken", loginResult.JwtRefreshToken, cookieOptionsRefreshJWT);

#if DEBUG
                    return Results.Ok(loginResult); // testing with JWT Token in Swagger - development ONLY!!!
#else
                    return Results.Ok(new { message = "Logged in successfully" });
#endif
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
                VerifyRequestCookiesExist(context);

                var loginResult = await authService.RefreshTokenAsync(context.Request.Cookies["jwtToken"]!, context.Request.Cookies["jwtRefreshToken"]!);

                if (loginResult.IsLoggedIn)
                {
                    //// reset the cookies in the response
                    //CookieOptions cookieOptionsJWT, cookieOptionsRefreshJWT;
                    //GenerateCookieOptions(loginResult, out cookieOptionsJWT, out cookieOptionsRefreshJWT);                    
                    //context.Response.Cookies.Append("jwtToken", loginResult.JwtToken, cookieOptionsJWT);
                    //context.Response.Cookies.Append("jwtRefreshToken", loginResult.JwtRefreshToken, cookieOptionsRefreshJWT);

#if DEBUG
                    return Results.Ok(loginResult); // testing with JWT Token in Swagger - development ONLY!!!
#else
                    return Results.Ok("Successfully refreshed JWT Bearer");
#endif                    
                }
                return Results.Unauthorized();
            })
            .WithName("RefreshTokenAsync")
            .RequireAuthorization()
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
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
            group.MapPost("/LogoutAsync", async Task<Results<Ok<string>, NotFound<string>>> (HttpContext context, IAuthService authService) =>
            {
                VerifyRequestCookiesExist(context);

                var response = await authService.LogoutAsync(context.Request.Cookies["jwtToken"]!);

                if (!response.IsLoggedIn) return TypedResults.Ok(response.Message);
                else return TypedResults.NotFound(response.Message);

            })
            .WithName("Logout")
            .RequireAuthorization()
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Logout user",
                Description = "Logout user and delete their cached JWT token.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
             *          Allow user to revoke the Refresh Token if they think it has been compromised               *
             *******************************************************************************************************/
            group.MapPost("/RevokeAsync", async Task<Results<Ok<string>, NotFound<string>>>  (HttpContext context, IAuthService authService) =>
            {
                VerifyRequestCookiesExist(context);

                // Revoke the Refresh Token
                var response = await authService.RevokeRefreshTokenAsync(context.Request.Cookies["jwtToken"]!);

                // was the Refresh Token revoked successfully
                if (!response.IsRefreshRevoked) return TypedResults.NotFound(response.Message);
                else return TypedResults.Ok(response.Message);

            })
            .WithName("Revoke")
            .RequireAuthorization()
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Revoke JWT Token",
                Description = "Revokes the JWT refresh token for the specified user.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });
        }

        //private static void GenerateCookieOptions(LoginRegisterRefreshResponseDto loginResult, out CookieOptions cookieOptionsJWT, out CookieOptions cookieOptionsRefreshJWT)
        //{
        //    // Set the JWT as a HttpOnly cookie
        //    cookieOptionsJWT = new CookieOptions
        //    {
        //        HttpOnly = true,
        //        IsEssential = true,
        //        Secure = true, // Ensures the cookie is sent over HTTPS
        //        SameSite = SameSiteMode.Strict, // Helps mitigate CSRF attacks                        
        //        Expires = loginResult.JwtTokenExpire
        //    };

        //    // Set the Refresh Token as a HttpOnly cookie
        //    cookieOptionsRefreshJWT = new CookieOptions
        //    {
        //        HttpOnly = true,
        //        IsEssential = true,
        //        Secure = true, // Ensures the cookie is sent over HTTPS
        //        SameSite = SameSiteMode.Strict, // Helps mitigate CSRF attacks                        
        //        Expires = loginResult.JwtRefreshTokenExpire

        //    };
        //}

        private static void VerifyRequestCookiesExist(HttpContext context)
        {
            // verify cookies exist in request
            if (context.Request.Cookies.ContainsKey("jwtToken") && context.Request.Cookies.ContainsKey("jwtRefreshToken"))
            {
                // guard that they are not empty
                Guard.Against.Empty(context.Request.Cookies["jwtToken"], "JWT must not be supplied");
                Guard.Against.Empty(context.Request.Cookies["jwtRefreshToken"], "Refresh token must not be supplied");
            }
            else throw new ArgumentException("JWT Token cookie must be supplied.");
        }
    }
}
