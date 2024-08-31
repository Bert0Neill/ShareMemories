﻿using Ardalis.GuardClauses;
using AutoMapper;
using Mailosaur.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;

namespace ShareMemories.API.Endpoints.Auth.Original
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
            group.MapPost("/RegisterAsync", async Task<Results<Ok<string>, BadRequest<string>>> (IMapper mapper, RegisterUserDto registerDto, IAuthService authService) =>
            {
                // convert DTO to Model
                var registerUserModel = mapper.Map<RegisterUserModel>(registerDto);

                // this gets back model and then converts into DTO
                var loginRegisterRefreshResponseModel = await authService.RegisterUserAsync(registerUserModel);

                // convert model to DTO
                var loginRegisterRefreshResponseDto = mapper.Map<LoginRegisterRefreshResponseDto>(loginRegisterRefreshResponseModel);

                if (loginRegisterRefreshResponseDto.IsStatus) return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.BadRequest(loginRegisterRefreshResponseDto.Message);

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
            group.MapPost("/LoginAsync", async (IMapper mapper, LoginUserDto loginDto, IAuthService authService, HttpContext context) =>
            {
                // var loginUserModel = mapper.Map<LoginUserModel>(loginDto);

                var loginRegisterRefreshResponseDto = await authService.LoginAsync(loginDto);

                if (loginRegisterRefreshResponseDto.IsStatus)
                {
#if DEBUG
                    return Results.Ok(loginRegisterRefreshResponseDto); // testing with JWT Token in Swagger - development ONLY!!!
#else
                    return Results.Ok(new { message = "Logged in successfully" });
#endif
                }

                return Results.BadRequest(loginRegisterRefreshResponseDto.Message);
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

                var loginRegisterRefreshResponseDto = await authService.RefreshTokenAsync(context.Request.Cookies["jwtToken"]!, context.Request.Cookies["jwtRefreshToken"]!);

                if (loginRegisterRefreshResponseDto.IsStatus)
                {

#if DEBUG
                    return Results.Ok(loginRegisterRefreshResponseDto); // testing with JWT Token in Swagger - development ONLY!!!
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

                var loginRegisterRefreshResponseDto = await authService.LogoutAsync(context.Request.Cookies["jwtToken"]!);

                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);

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
            group.MapPost("/RevokeAsync", async Task<Results<Ok<string>, NotFound<string>>> (HttpContext context, IAuthService authService) =>
            {
                VerifyRequestCookiesExist(context); // before revoking, make sure they exist

                var loginRegisterRefreshResponseDto = await authService.RevokeTokenLogoutAsync(context.Request.Cookies["jwtToken"]!);

                // was the Refresh Token revoked successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
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

                var loginRegisterRefreshResponseDto = await authService.VerifyEmailConfirmationAsync(userName, token);

                // was the email confirmation successful
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
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
            group.MapPost("/VerifyPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, string token, string newPassword, string oldPassword, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Email is missing");
                Guard.Against.Empty(newPassword, "Password is missing");
                Guard.Against.Empty(token, "Password reset token is missing");

                var loginRegisterRefreshResponseDto = await authService.VerifyPasswordResetAsync(userName, token, newPassword, oldPassword);

                // was the email confirmation successful
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
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
            group.MapPost("/RequestPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.RequestPasswordResetAsync(userName);

                // was the password reset email sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
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

                var loginRegisterRefreshResponseDto = await authService.RequestConfirmationEmailAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("ResendConfirmationEmail")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Request new email confirmation",
                Description = "Request a new email confirmation, to complete registration",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });


            /*******************************************************************************************************
             *   Verify user's 2FA (API not secure as user must be able to use it as part of logged in process)    *
             *To verify 2FA code, it has to be form the same browser tab that initiated - thus an code entry screen* 
             *******************************************************************************************************/
            group.MapPost("/Verify2FactorAuthenticationAsync", async Task<Results<Ok<string>, NotFound<string>>> (IAuthService authService, string userName, string code) =>
            {
                Guard.Against.Empty(userName, "Username is missing");
                Guard.Against.Empty(code, "Code is missing");

                var loginRegisterRefreshResponseDto = await authService.Verify2FactorAuthenticationAsync(userName, code);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
             .WithName("Verify2FactorAuthentication")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Verify user login with 2FA",
                Description = "Allow user to authenticate themselves using a code that was emailed to them, as part of the login process (if enabled)",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
            *                           Enforce 2FA for a specific user (called by Admin)                          *
            *******************************************************************************************************/
            group.MapPost("/Enable2faForUserAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.Enable2FactorAuthenticationForUserAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);

            })
            .WithName("Enable2faForUser")
            .RequireAuthorization("AdminPolicy") // apply a security policy to API's and a default Bearer Scheme
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Enable 2FA for a user",
                Description = "Admin can enable 2FA for a user",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /******************************************************************************************************
            *                         Revoke 2FA for a specific user (called by Admin)                            *
            *******************************************************************************************************/
            group.MapPost("/Disable2faForUserAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.Disable2FactorAuthenticationForUserAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("Disable2faForUser")
            .RequireAuthorization("AdminPolicy") // apply a security policy to API's and a default Bearer Scheme
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Disable 2FA for a user",
                Description = "Admin can disable 2FA for a user",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /******************************************************************************************************
            *                             Unlock a user's account (called by Admin)                               *
            *******************************************************************************************************/
            group.MapPost("/UnlockAccountAsync/{userName}", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.UnlockAccountVerifiedByAdminAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("Unlock Account - Admin")
            .RequireAuthorization("AdminPolicy") // apply a security policy to API's and a default Bearer Scheme
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Admin unlock a User's account",
                Description = "A feature where an Admin can unlock a User's account",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /******************************************************************************************************
            *                             Lock a user's account (called by Admin)                               *
            *******************************************************************************************************/
            group.MapPost("/LockAccountAsync/{userName}", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.LockAccountAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("Lock Account - Admin")
            .RequireAuthorization("AdminPolicy") // apply a security policy to API's and a default Bearer Scheme
            .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Lock a user's account",
                Description = "Admin can disable 2FA for a user",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /******************************************************************************************************
            *            User request's their account to be unlocked (email conformation sent)                    *
            *******************************************************************************************************/
            group.MapPost("/UnlockRequestAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.RequestUnlockAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("Unlock Request")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "User request to unlock their account",
                Description = "A user requests to unlock their account - email sent with link",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /******************************************************************************************************
            *         Verify email link to unlock account (user will have gotten an email to verify)              *
            *******************************************************************************************************/

            group.MapPost("/UnlockRequestVerifiedByEmailAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, string token, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");
                Guard.Against.Empty(token, "Token is missing");

                var loginRegisterRefreshResponseDto = await authService.UnlockAccountVerifiedByEmailAsync(userName, token);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("Unlock Request Verified By Email")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Unlock a user's account",
                Description = "Admin can unlock a user's account",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });
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
