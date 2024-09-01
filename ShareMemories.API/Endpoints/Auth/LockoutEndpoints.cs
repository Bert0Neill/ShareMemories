using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi.Models;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.API.Endpoints.Auth
{
    public static class LockoutEndpoints
    {
        public static void MapLockoutEndpoints(this IEndpointRouteBuilder routes)
        {
            var lockoutGroup = routes.MapGroup("lockoutGroup").WithOpenApi();

            /**********************************************************************************************************
            *  User request's their account to be unlocked (email conformation sent) - user has no JWT at this stage  *
            ***********************************************************************************************************/
            lockoutGroup.MapPost("/UnlockRequestAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.RequestUnlockAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("UnlockRequestAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "User request to unlock their account",
                Description = "A user requests to unlock their account - email sent with link",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Lockout - API Library" } }
            });

            /******************************************************************************************************************
            * Verify email link to unlock account (user will have gotten an email to verify) - user has no JWT at this stage  *
            *******************************************************************************************************************/

            lockoutGroup.MapGet("/UnlockRequestVerifiedByEmailAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, string token, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");
                Guard.Against.Empty(token, "Token is missing");

                var loginRegisterRefreshResponseDto = await authService.UnlockAccountVerifiedByEmailAsync(userName, token);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })                
            .WithName("UnlockRequestVerifiedByEmailAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Unlock a user's account",
                Description = "Admin can unlock a user's account",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Lockout - API Library" } }
            });
        }
    }
}
