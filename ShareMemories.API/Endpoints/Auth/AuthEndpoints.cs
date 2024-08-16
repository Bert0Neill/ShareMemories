using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;

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

                if (result.IsStatus) return TypedResults.Ok(result.Message);
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

                if (loginResult.IsStatus)
                {
#if DEBUG
                    return Results.Ok(loginResult); // testing with JWT Token in Swagger - development ONLY!!!
#else
                    return Results.Ok(new { message = "Logged in successfully" });
#endif
                }

                return Results.BadRequest(loginResult.Message);
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

                if (loginResult.IsStatus)
                {

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

                if (!response.IsStatus) return TypedResults.Ok(response.Message);
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
                var response = await authService.RevokeTokenLogoutAsync(context.Request.Cookies["jwtToken"]!);

                // was the Refresh Token revoked successfully
                if (!response.IsRefreshRevoked) return TypedResults.NotFound(response.Message);
                else return TypedResults.Ok(response.Message);

            })
            .WithName("Revoke")
            .RequireAuthorization()
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Revoke JWT & Refresh Token",
                Description = "Revokes the JWT refresh token for the specified user.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
             *              Allow user to confirm their email address, stop fraud and bogus accounts               *
             *******************************************************************************************************/
            group.MapGet("/ConfirmEmailAsync", async Task<Results<Ok<string>, NotFound<string>>> (IAuthService authService, string userName, string token) =>
            {
                Guard.Against.Empty(userName, "Username is missing");
                Guard.Against.Empty(token, "Confirm token is missing");

                var response = await authService.VerifyEmailConfirmationAsync(userName, token);

                // was the email confirmation successful
                if (!response.IsStatus) return TypedResults.NotFound(response.Message);
                else return TypedResults.Ok(response.Message);
                
            })
            .WithName("ConfirmEmail")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Confirm Email",
                Description = "Confirms the user's email address with the provided token, after they have registered.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
             *          Verify password reset (this will be called by email link to with new password)             *
             *******************************************************************************************************/
            group.MapPost("/VerifyPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, string token, string password, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Email is missing");
                Guard.Against.Empty(password, "Password is missing");
                Guard.Against.Empty(token, "Password reset token is missing");

                var response = await authService.VerifyPasswordResetAsync(userName, token, password);

                // was the email confirmation successful
                if (!response.IsStatus) return TypedResults.NotFound(response.Message);
                else return TypedResults.Ok(response.Message);
            })
            .WithName("VerifyPasswordReset")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Called by clicking on a link in an email",
                Description = "Request a password reset email.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
             *          Request password reset (this will send an email with a link to reset password)             *
             *******************************************************************************************************/
            group.MapGet("/RequestPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var response = await authService.RequestPasswordResetAsync(userName);

                // was the password reset email sent successfully
                if (!response.IsStatus) return TypedResults.NotFound(response.Message);
                else return TypedResults.Ok(response.Message);
            })
            .WithName("RequestPasswordReset")
            .RequireAuthorization()
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Request an email with a link to reset the password",
                Description = "Request a password reset email.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });


            /*******************************************************************************************************
             *          Request that a new confirmation email be sent (to complete registration process            *
             *******************************************************************************************************/
            group.MapGet("/ResendConfirmationEmailAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var response = await authService.RequestConfirmationEmailAsync(userName);

                // was the email confirmation sent successfully
                if (!response.IsStatus) return TypedResults.NotFound(response.Message);
                else return TypedResults.Ok(response.Message);
            })
            .WithName("ResendConfirmationEmail")
            //.RequireAuthorization()
            //.WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Request new email confirmation",
                Description = "Request a new email confirmation, to complete registration",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });
            

            ///*******************************************************************************************************
            // *                                  2 Factor Authentication Actions                                    *
            // *******************************************************************************************************/
            //group.MapPost("/enable-2fa", async (UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, string userId, string code) =>
            //{
            //    var user = await userManager.FindByIdAsync(userId);
            //    if (user == null)
            //    {
            //        return Results.NotFound("User not found.");
            //    }

            //    var is2faTokenValid = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, code);
            //    if (!is2faTokenValid)
            //    {
            //        return Results.BadRequest("Invalid 2FA code.");
            //    }

            //    user.TwoFactorEnabled = true;
            //    var result = await userManager.UpdateAsync(user);

            //    if (result.Succeeded)
            //    {
            //        return Results.Ok("2FA is enabled for the user.");
            //    }

            //    return Results.BadRequest("Failed to enable 2FA.");
            //});

            //group.MapGet("/generate-2fa-code", async (UserManager<IdentityUser> userManager, string userId) =>
            //{
            //    var user = await userManager.FindByIdAsync(userId);
            //    if (user == null)
            //    {
            //        return Results.NotFound("User not found.");
            //    }

            //    if (!user.TwoFactorEnabled)
            //    {
            //        return Results.BadRequest("2FA is not enabled for this user.");
            //    }

            //    var code = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider);
            //    return Results.Ok(new { Code = code });
            //});

            //group.MapPost("/verify-2fa", async (UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, string userId, string code) =>
            //{
            //    var user = await userManager.FindByIdAsync(userId);
            //    if (user == null)
            //    {
            //        return Results.NotFound("User not found.");
            //    }

            //    var result = await signInManager.TwoFactorSignInAsync(TokenOptions.DefaultAuthenticatorProvider, code, isPersistent: false, rememberClient: false);

            //    if (result.Succeeded)
            //    {
            //        return Results.Ok("2FA verification successful.");
            //    }
            //    else if (result.IsLockedOut)
            //    {
            //        return Results.StatusCode(423); // User account locked out.
            //    }
            //    else
            //    {
            //        return Results.BadRequest("Invalid 2FA code.");
            //    }
            //});

        }

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
