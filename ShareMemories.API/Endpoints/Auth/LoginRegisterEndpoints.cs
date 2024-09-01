using Ardalis.GuardClauses;
using AutoMapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;
using System.Security.Claims;

namespace ShareMemories.API.Endpoints.Auth
{
    public static class LoginRegisterEndpoints
    {
        public static void MapLoginRegisterEndpoints(this IEndpointRouteBuilder routes)
        {
            var loginRegisterGroup = routes.MapGroup("loginGroup").WithOpenApi();

            /*******************************************************************************************************
             * Register a new user (adding FluentValidator to ensure data integrity from client)
             *******************************************************************************************************/
            loginRegisterGroup.MapPost("/RegisterAsync", async Task<Results<Ok<string>, BadRequest<string>>> (IMapper mapper, RegisterUserDto registerDto, IAuthService authService) =>
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
            loginRegisterGroup.MapPost("/LoginAsync", async (IMapper mapper, LoginUserDto loginDto, IAuthService authService, HttpContext context) =>
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
                Summary = "Login a user",
                Description = "Logs in the user and returns a JWT token if successful.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            })
            .CacheOutput(x => x.Tag("LoginUser"))
            .AddEndpointFilter<GenericValidationFilter<LoginUserValidator, LoginUserDto>>(); // apply fluent validation to DTO model from client and pass back broken rules    

            /*******************************************************************************************************
            *                           Allow user to logout and delete their JWT Token                            *
            *******************************************************************************************************/
            // Define the logout endpoint
            loginRegisterGroup.MapPost("/LogoutAsync", async Task<Results<Ok<string>, NotFound<string>>> (HttpContext context, IAuthService authService) =>
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
                Summary = "Logout a user",
                Description = "Logout user and delete their cached JWT token.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
             *      Allow user to confirm their registered email address, stop fraud and bogus accounts            *
             *******************************************************************************************************/
            loginRegisterGroup.MapGet("/ConfirmRegisteredEmailAsync", async Task<Results<Ok<string>, NotFound<string>>> (IAuthService authService, string userName, string token) =>
            {
                Guard.Against.Empty(userName, "Username is missing");
                Guard.Against.Empty(token, "Confirm token is missing");

                var loginRegisterRefreshResponseDto = await authService.VerifyEmailConfirmationAsync(userName, token);

                // was the email confirmation successful
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .WithName("ConfirmRegisteredEmailAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Confirm a new registered user's email",
                Description = "Confirms the user's email address with the provided token, after they have registered.",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
             *          Request that a new confirmation email be sent (to complete registration process            *
             *******************************************************************************************************/
            loginRegisterGroup.MapPost("/ResendConfirmationEmailAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
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
                Summary = "Request a new user's registered email confirmation",
                Description = "Request a new email confirmation, to complete registration",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
             *              Update User's details (Name, email, phone number for e.g.)               *
             *******************************************************************************************************/
            loginRegisterGroup.MapPut("/UpdateUserDetailsAsync", async Task<Results<Ok<string>, NotFound<string>>> (HttpContext context, UpdateUserDetailsDto userUpdateDetails, IAuthService authService) =>
            {
                Guard.Against.Null(userUpdateDetails, nameof(userUpdateDetails));

                var loginRegisterRefreshResponseDto = await authService.UpdateUserDetailsAsync(context.Request.Cookies["jwtToken"]!, userUpdateDetails);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .RequireAuthorization()
            .WithName("UpdateUserDetailsAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Update user's details",
                Description = "Update Email, Phone, First Name, Last Name or DOB",
                Tags = new List<OpenApiTag> { new OpenApiTag { Name = "Login/Register/Refresh API Library" } }
            });

            /*******************************************************************************************************
            *                       View User's details (Name, email, phone number for e.g.)                       *
            *******************************************************************************************************/
            loginRegisterGroup.MapGet("/ViewUserDetailsAsync", async Task<Results<Ok<string>, NotFound<string>>> (string userName, IAuthService authService) =>
            {
                Guard.Against.Empty(userName, "Username is missing");

                var loginRegisterRefreshResponseDto = await authService.ViewUserDetailsAsync(userName);

                // was the email confirmation sent successfully
                if (!loginRegisterRefreshResponseDto.IsStatus) return TypedResults.NotFound(loginRegisterRefreshResponseDto.Message);
                else return TypedResults.Ok(loginRegisterRefreshResponseDto.Message);
            })
            .RequireAuthorization()
            .WithName("ViewUserDetailsAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "View user's details",
                Description = "View Email, Phone, First Name, Last Name, Roles and DOB",
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
