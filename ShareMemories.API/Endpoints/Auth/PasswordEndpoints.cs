using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi.Models;
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
            passwordGroup.MapPost("/VerifyPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (HttpContext context, string token, string newPassword, string oldPassword, IAuthService authService) =>
            {
                Guard.Against.Empty(oldPassword, "Old password is missing");
                Guard.Against.Empty(newPassword, "New password is missing");
                Guard.Against.Empty(token, "Password reset token is missing");

                var loginRegisterRefreshResponseDto = await authService.VerifyPasswordResetAsync(context.Request.Cookies["jwtToken"]!, token, newPassword, oldPassword);

                // was the email confirmation successful
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("VerifyPasswordResetAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Redirected to API by a link within an email - thus appropriate user gets link",
                Description = "Request a password reset email.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Password - API Library" } }
            });


            /*******************************************************************************************************
             *          Request password reset (this will send an email with a link to reset password)             *
             *******************************************************************************************************/
            passwordGroup.MapPost("/RequestPasswordResetAsync", async Task<Results<Ok<string>, NotFound<string>>> (HttpContext context, IAuthService authService) =>
            {
                var loginRegisterRefreshResponseDto = await authService.RequestPasswordResetAsync(context.Request.Cookies["jwtToken"]!);

                // was the password reset email sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("RequestPasswordResetAsync")
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
