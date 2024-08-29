using Ardalis.GuardClauses;
using AutoMapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.API.Endpoints.Auth
{
    public static class PasswordEndpoints
    {
        public static void MapPasswordEndpoints(this IEndpointRouteBuilder routes)
        {           
            var passwordGroup = routes.MapGroup("passwordGroup").WithOpenApi();

            /*******************************************************************************************************
             *          Verify password reset (this will be called by email link to with new password)             *
             *******************************************************************************************************/
            passwordGroup.MapPost("/VerifyPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, string token, string password, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Email is missing");
                Guard.Against.Empty(password, "Password is missing");
                Guard.Against.Empty(token, "Password reset token is missing");

                var loginRegisterRefreshResponseDto = await authService.VerifyPasswordResetAsync(userName, token, password);

                // was the email confirmation successful
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("VerifyPasswordReset")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Redirected to API by a link within an email - thus appropriate user gets link",
                Description = "Request a password reset email.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Password - API Library" } }
            });

            /*******************************************************************************************************
             *          Request password reset (this will send an email with a link to reset password)             *
             *******************************************************************************************************/
            passwordGroup.MapPost("/RequestPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
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
                Summary = "User requests an email with a link to reset the password - calls VerifyPasswordResetAsync API",
                Description = "Request a password reset email.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Password - API Library" } }
            });
        }
    }
}
