using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi.Models;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.API.Endpoints.Auth
{
    public static class AdminEndpoints
    {
        public static void MapAdminEndpoints(this IEndpointRouteBuilder routes)
        {
            var adminGroup = routes.MapGroup("adminGroup").WithOpenApi();

            /*******************************************************************************************************
            *                           Enforce 2FA for a specific user (called by Admin)                          *
            *******************************************************************************************************/
            adminGroup.MapPost("/Enable2faForUserAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
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
                Summary = "Admin enable 2FA for a user",
                Description = "Admin can enable 2FA for a user",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Admin - API Library" } }
            });

            /******************************************************************************************************
            *                         Revoke 2FA for a specific user (called by Admin)                            *
            *******************************************************************************************************/
            adminGroup.MapPost("/Disable2faForUserAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
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
                Summary = "Admin disable 2FA for a user",
                Description = "Admin can disable 2FA for a user",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Admin - API Library" } }
            });

           /******************************************************************************************************
           *                             Unlock a user's account (called by Admin)                               *
           *******************************************************************************************************/
            adminGroup.MapPost("/UnlockAccountAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
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
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Admin - API Library" } }
            });

            /******************************************************************************************************
            *                             Lock a user's account (called by Admin)                               *
            *******************************************************************************************************/
            adminGroup.MapPost("/LockAccountAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
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
                Summary = "Admin lock a user's account",
                Description = "Admin can disable 2FA for a user",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Admin - API Library" } }
            });
        }
    }
}
