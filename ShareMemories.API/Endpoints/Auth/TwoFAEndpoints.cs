using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi.Models;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.API.Endpoints.Auth
{
    public static class TwoFAEndpoints
    {
        public static void MapTwoFAEndpoints(this IEndpointRouteBuilder routes)
        {            
            var twoFAGroup = routes.MapGroup("twoFAGroup").WithOpenApi();           

            /*******************************************************************************************************
             *   Verify user's 2FA (API not secure as user must be able to use it as part of logged in process)    *
             *To verify 2FA code, it has to be form the same browser tab that initiated - thus an code entry screen* 
             *******************************************************************************************************/
            twoFAGroup.MapPost("/Verify2FactorAuthenticationAsync", async Task<Results<Ok<string>, NotFound<string>>> (IAuthService authService, string userName, string code) =>
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
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "2FA - API Library" } }
            });

            /*******************************************************************************************************
             *                    Request that a new 2FA code be sent to the user                                  *
             *******************************************************************************************************/
            twoFAGroup.MapPost("/Request2FACodeAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var twoFaResponseDto = await authService.Request2FACodeAsync(userName);

                // was the 2FA code sent successfully
                if (!twoFaResponseDto.IsStatus) return TypedResults.NotFound(twoFaResponseDto.Message);
                else return TypedResults.Ok(twoFaResponseDto.Message);
            })
            .WithName("Request2FACodeAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Request new 2FA code",
                Description = "Request a new 2FA code to be sent to the user",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "2FA - API Library" } }
            });

        }
    }
}
