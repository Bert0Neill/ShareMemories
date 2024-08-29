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
    public static class TokenEndpoints
    {
        public static void MapTokenEndpoints(this IEndpointRouteBuilder routes)
        {
            var tokenGroup = routes.MapGroup("tokenGroup").WithOpenApi();

            /*******************************************************************************************************
            * Refresh a user's login instance, without having to pass the credentials again
            *******************************************************************************************************/
            tokenGroup.MapPost("/RefreshTokenAsync", async (IAuthService authService, HttpContext context) =>
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
                Summary = "Renew JWT & Refresh token",
                Description = "Using refresh & JWT token, you can request to be logged back in again, without having to supply credentials.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Token - API Library" } }
            });

            /*******************************************************************************************************
             *          Allow user to revoke the Refresh Token if they think it has been compromised               *
             *******************************************************************************************************/
            tokenGroup.MapPost("/RevokeAsync", async Task<Results<Ok<string>, NotFound<string>>> (HttpContext context, IAuthService authService) =>
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
                Summary = "Revoke JWT & Refresh token",
                Description = "Revokes the JWT refresh token for the specified user.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Token - API Library" } }
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
