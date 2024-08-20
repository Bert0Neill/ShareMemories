﻿using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.Resources;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Entities;
using ShareMemories.Domain.Enums;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using System;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace ShareMemories.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        // class variables
        private readonly UserManager<ExtendIdentityUser> _userManager;
        private readonly SignInManager<ExtendIdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IOptions<IdentityOptions> _identityOptions;
        private readonly IConfiguration _config;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailSender _emailSender;
        private readonly IMemoryCache _memoryCache;
        private readonly ILogger<AuthService> _logger;
        private bool _isRefreshing = false;
        public AuthService(ILogger<AuthService> logger, IMemoryCache memoryCache, IOptions<IdentityOptions> identityOptions, RoleManager<IdentityRole> roleManager, UserManager<ExtendIdentityUser> userManager, IConfiguration config, IJwtTokenService jwtTokenService, SignInManager<ExtendIdentityUser> signInManager, IHttpContextAccessor httpContextAccessor, IEmailSender emailSender)
        {
            _userManager = userManager;
            _config = config;
            _jwtTokenService = jwtTokenService;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _identityOptions = identityOptions;
            _httpContextAccessor = httpContextAccessor;
            _emailSender = emailSender;
            _memoryCache = memoryCache;
            _logger = logger;
    }

        #region APIs

        /**************************************************************************************************
        *           Register, Login, Logout, Verify Confirm Email & Request Confirm Email                 *
        ***************************************************************************************************/
        public async Task<LoginRegisterRefreshResponseModel> RegisterUserAsync(RegisterUserModel user)
        {
            Guard.Against.Null(user, null, "User credentials are not valid");

            const string DEFAULT_ROLE = "User";
            LoginRegisterRefreshResponseModel registerResponseModel = new() { Message = $"Username: {user.UserName} registered successfully. You can now login" };

            // verify that Username and\or email have not already been registered
            if (await IsUsernameOrEmailTakenAsync(user.UserName, user.Email))
            {
                registerResponseModel.Message = $"Username {user.UserName} or Email {user.Email}, already exists within the system";
                return registerResponseModel;
            }

            // add these details to a new AspNetUser table instance
            var identityUser = new ExtendIdentityUser
            {
                UserName = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                DateOfBirth = user.DateOfBirth,
                LastUpdated = DateTimeOffset.UtcNow.UtcDateTime,
                EmailConfirmed = !_identityOptions.Value.SignIn.RequireConfirmedEmail,
                //TwoFactorEnabled = bool.Parse(_config.GetSection("SystemDefaults:Is2FAEnabled").Value!)                
                TwoFactorEnabled = true
            };

            if (await _roleManager.RoleExistsAsync(DEFAULT_ROLE)) // verify that the role exists
            {
                var result = await _userManager.CreateAsync(identityUser, user.Password);

                if (result.Errors.Any())
                {
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    registerResponseModel.Message = errors.ToString();
                }
                else // success - assign default role
                {
                    // assign a default role (USER) to the user
                    var roleAssignResult = await _userManager.AddToRoleAsync(identityUser, "User"); // Replace "User" with the desired role

                    if (roleAssignResult.Errors.Any())
                    {
                        var roleErrors = new StringBuilder();
                        roleAssignResult.Errors.ToList().ForEach(err => roleErrors.AppendLine($"{err.Description}"));
                        registerResponseModel.Message = $"Username: {user.UserName} registered, but there was an issue assigning roles: {roleErrors}";
                    }
                    else // success registering user & role
                    {
                        // does the user need to confirm their email (OTP)
                        if (_identityOptions.Value.SignIn.RequireConfirmedEmail)
                        {                            
                            string verificationCode = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser); // generate token to be used in URL
                            await SendEmailTaskAsync(identityUser, verificationCode, EmailType.ConfirmationEmail);
                            registerResponseModel.Message = $"Username: {user.UserName} registered successfully. A confirmation email has been sent to {identityUser.Email}, you will need to click the link within the email to complete the registration process. Check your Spam folder if it isn't in your Inbox.";
                        }        
                        
                        registerResponseModel.IsStatus = true; // doubling up the IsLoggedIn property to indicate if user was successfully registered or not
                    }
                }
            }
            else
            {
                // notify user that the role doesn't exist
                registerResponseModel.Message = $"Role: {DEFAULT_ROLE} - doesn't exist.";
            }

            return registerResponseModel;
        }

        public async Task<LoginRegisterRefreshResponseDto> LoginAsync(LoginUserDto user)
        {
            Guard.Against.Null(user, null, "User credentials are not valid");   

            var response = new LoginRegisterRefreshResponseDto(); // "IsStatus" will be false by default
            var identityUser = await _userManager.FindByNameAsync(user.UserName);

            if (identityUser is null)
            {                
                response.Message = $"Credentials are not valid";
                return response;
            }            

            // does the the user still need to confirmed their email (if applicable)
            if (_identityOptions.Value.SignIn.RequireConfirmedEmail && !await _userManager.IsEmailConfirmedAsync(identityUser))
            {
                response.Message = $"User has not yet confirmed their email address. Check your Spam folder";
                return response;                
            }

            await ValidateUserIdentityAsync(user, identityUser); // checks to verify a valid user - a BadRequest is thrown otherwise            
            IList<string> roles = await VerifyUserRolesAsync(identityUser); // retrieve their roles (at least 1 must exist)

            // try to sign the user in
            await _signInManager.SignOutAsync();
            SignInResult loginResult = await _signInManager.PasswordSignInAsync(identityUser!, user.Password, false, true);

            if (loginResult.IsLockedOut || loginResult.IsNotAllowed)
            {
                response.Message = $"Account is either locked (wait {_identityOptions.Value.Lockout.DefaultLockoutTimeSpan} minutes) or you are not allowed to sign-in - contact Administration.";
            }
            else if (loginResult.RequiresTwoFactor) // valid user at this stage - determine if 2FA is enabled and halt login- send 2fa email
            {
                await SendTwoFactorAuthenticationAsync(identityUser!);
                response.Message = "Two-factor authentication is enabled on your account. You have been sent an email with a OTP, click on the link to complete your login.";
            }
            else if (loginResult.Succeeded)
            {
                // if "remember me" is true from client, extent their login 
                if (user.IsPersistent)
                {
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(int.Parse(_config.GetSection("SystemDefaults:RememberMeLifeSpan").Value!)) // Set expiration to days
                    };                 

                    // sign-in again with extended duration
                    await _signInManager.SignInAsync(identityUser, authProperties);
                }

                await AssignJwtTokensResponse(response, identityUser, roles); // create JWT bearer
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> LogoutAsync(string jwtToken)
        {
            Guard.Against.Null(jwtToken, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "Successfully logged out" }; // default message

            var principal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

            // not able to retrieve user from Jwt bearer token
            if (principal?.Identity?.Name is null)
            {
                response.IsStatus = true; // user is still logged in
                response.Message = "Jwt Bearer not valid, during logout process";
            }
            else
            {
                var identityUser = await _userManager.FindByNameAsync(principal.Identity.Name); // retrieve user principal

                // clear the refresh token
                identityUser!.RefreshToken = null;
                identityUser.RefreshTokenExpiry = null;
                identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

                var result = await _userManager.UpdateAsync(identityUser); // Update the user in the database

                // handle a database fail
                if (!result.Succeeded)
                {
                    response.IsStatus = true; // user is still logged in
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
                else
                {
                    // remove cookies form response to client
                    await _signInManager.SignOutAsync();
                    _httpContextAccessor.HttpContext?.Response.Cookies.Delete("jwtToken");
                    _httpContextAccessor.HttpContext?.Response.Cookies.Delete("jwtRefreshToken");
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> VerifyEmailConfirmationAsync(string userName, string token)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");
            Guard.Against.Null(token, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "Email confirmation successful, you can now login." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);
            if (identityUser == null) response.Message = "Invalid credentials or token";
            else
            {
                var result = await _userManager.ConfirmEmailAsync(identityUser, token);

                if (result.Succeeded)
                {
                    response.IsStatus = true;
                }
                else
                {
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> RequestConfirmationEmailAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"A new confirmation email has been sent - check your Spam folder." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                if (identityUser.EmailConfirmed)
                {
                    response.Message = "Email address associated with your Username, has already been confirmed.";
                }
                else
                {
                    string verificationCode = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser); // generate token to be used in URL
                    await SendEmailTaskAsync(identityUser, verificationCode, EmailType.ConfirmationEmail);
                    response.IsStatus = true;
                }
            }

            return response;
        }

        /******************************************************
        *               JWT Refresh & Revoke                  *
        *******************************************************/

        public async Task<LoginRegisterRefreshResponseDto> RefreshTokenAsync(string jwtToken, string refreshToken)
        {
            var response = new LoginRegisterRefreshResponseDto();

            try
            {
                if (!_isRefreshing) // stop user refresh saturation \ disable client side button that calls API too
                {
                    _isRefreshing = true;

                    var principal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

                    // not able to retrieve user from Jwt token
                    if (principal?.Identity?.Name is null)
                    {
                        await LogoutAsync(jwtToken); // call logout
                        response.Message = "Jwt Bearer is not valid";
                        return response;
                    }

                    var identityUser = await _userManager.FindByNameAsync(principal.Identity.Name);

                    if (identityUser is null || identityUser.RefreshToken != refreshToken || identityUser.RefreshTokenExpiry < DateTime.Now)
                    {
                        await LogoutAsync(jwtToken); // call logout
                        response.Message = "Jwt Bearer invalid or invalid Refresh Token or Refresh Token expired - Use the login screen again";
                        return response;
                    }

                    var roles = await _userManager.GetRolesAsync(identityUser); // retrieve role(s) to append to Claims in JWT bearer token

                    response.IsStatus = true;
                    response.JwtToken = _jwtTokenService.GenerateJwtToken(identityUser, roles, int.Parse(_config["Jwt:JWT_TOKEN_EXPIRE_MINS"]!));
                    response.JwtRefreshToken = _jwtTokenService.GenerateRefreshToken();
                    response.JwtRefreshTokenExpire = DateTimeOffset.UtcNow.AddDays(int.Parse(_config["Jwt:REFRESH_TOKEN_EXPIRE_DAYS"]!)).UtcDateTime;
                    response.JwtTokenExpire = DateTimeOffset.UtcNow.AddMinutes(int.Parse(_config["Jwt:JWT_TOKEN_EXPIRE_MINS"]!)).UtcDateTime;

                    // update AspNetUser DB table with latest details 
                    identityUser.RefreshToken = response.JwtRefreshToken;
                    identityUser.RefreshTokenExpiry = response.JwtRefreshTokenExpire; // refresh token should be longer than JWT bearer token
                    identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

                    var result = await _userManager.UpdateAsync(identityUser);
                    if (!result.Succeeded)
                    {
                        response.IsStatus = true; // user is still logged in
                        var errors = new StringBuilder();
                        result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                        response.Message = errors.ToString();
                    }
                    else
                    {
                        UpdateResponseTokens(response);
                    }

                    return response;
                }
                else
                {
                    // Return a response in case the token is already refreshing
                    response.Message = "Token is already refreshing.";
                    return response;
                }
            }
            finally { _isRefreshing = false; } // reset for next refresh call
        }

        public async Task<LoginRegisterRefreshResponseDto> RevokeTokenLogoutAsync(string jwtToken)
        {
            Guard.Against.Null(jwtToken, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "Successfully revoked JWT token", IsStatus = true }; // default message

            var claimsPrincipal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

            // not able to retrieve user from Jwt bearer token
            if (claimsPrincipal?.Identity?.Name is null)
            {                
                response.IsStatus = false;
                response.Message = "Jwt Bearer is not valid, during revoke process";
            }
            else
            {
                var identityUser = await _userManager.FindByNameAsync(claimsPrincipal.Identity.Name); // retrieve user principal

                if (identityUser is null)
                {
                    response.IsStatus = false;
                    response.Message = $"User '{claimsPrincipal.Identity.Name}' not found during token revoke";
                    return response;
                }

                // clear the refresh token & update database
                identityUser!.RefreshToken = null;
                identityUser.RefreshTokenExpiry = null;
                identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

                var result = await _userManager.UpdateAsync(identityUser); // update database

                // handle a database fail
                if (!result.Succeeded)
                {
                    response.IsStatus = false;
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
                else // success
                {
                    // sign out & remove cookies from response to client - force user to log back in (thus generating new tokens)
                    await _signInManager.SignOutAsync();
                    _httpContextAccessor.HttpContext?.Response.Cookies.Delete("jwtToken");
                    _httpContextAccessor.HttpContext?.Response.Cookies.Delete("jwtRefreshToken");

                    CacheRevokedToken(jwtToken, response, claimsPrincipal); // cache revoked Jwt so that an imposter can't use it (middleware checks API calls)
                }
            }
            return response;
        }

        /******************************************************
        *           Password reset request & Verify           *
        *******************************************************/

        public async Task<LoginRegisterRefreshResponseDto> VerifyPasswordResetAsync(string userName, string token, string password)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");
            Guard.Against.Null(token, null, "Token is not valid");
            Guard.Against.Null(password, null, "Password is not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "Password was reset successfully." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);
            if (identityUser == null) response.Message = "Invalid credentials or token";
            else
            {
                var result = await _userManager.ResetPasswordAsync(identityUser, token, password);

                if (result.Succeeded) response.IsStatus = true;
                else
                {
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
            }

            return response;
        }
        
        public async Task<LoginRegisterRefreshResponseDto> RequestPasswordResetAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"A password reset request has been sent to user - {userName}." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "An invalid email or the email is not register to your account";
            else
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser);
                await SendEmailTaskAsync(identityUser, token, EmailType.PasswordReset);
                response.IsStatus = true; // double up for validating password sent successfully
            }

            return response;
        }

        /******************************************************
        *         Enable & Disable 2FA on account             *
        *******************************************************/

        public async Task<LoginRegisterRefreshResponseDto> Enable2FactorAuthenticationForUserAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"User {userName} has had their 2FA enabled." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                var is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(identityUser);

                if (is2faEnabled)
                {                    
                    response.Message = $"2FA is already enabled for user {userName}.";
                }
                else
                {
                    var result = await _userManager.SetTwoFactorEnabledAsync(identityUser, true); // enable 2FA in DB

                    if (result.Succeeded)
                    {
                        response.IsStatus = true;

                        // send user email to notify them that they have 2FA enabled                        
                        await SendEmailTaskAsync(identityUser, string.Empty, EmailType.TwoFactorAuthenticationEnabled);
                    }
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> Disable2FactorAuthenticationForUserAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"User {userName} has had their 2FA disabled." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                var is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(identityUser);

                if (!is2faEnabled)
                {
                    response.Message = $"2FA has already been disabled for user {userName}.";
                }
                else
                {
                    var result = await _userManager.SetTwoFactorEnabledAsync(identityUser, false); // disable 2FA in DB

                    if (result.Succeeded)
                    {
                        response.IsStatus = true;

                        // send user email to notify them that they have 2FA enabled                        
                        await SendEmailTaskAsync(identityUser, string.Empty, EmailType.TwoFactorAuthenticationDisabled);
                    }                    
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> Verify2FactorAuthenticationAsync(string userName, string verificationCode)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");
            Guard.Against.Null(verificationCode, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "2FA verification successful. You have been verified, you can now call the (secure) API's" }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null)
            {
                response.Message = "User not found.";
            }
            else
            {
                // retrieve existing providers and check that Email is one of them (you may want to use SMS etc.)
                var providers = await _userManager.GetValidTwoFactorProvidersAsync(identityUser);
                if (!providers.Contains("Email"))
                {
                    response.Message = "Expected 2FA Provider doesn't exist!";
                }

                var result = await _signInManager.TwoFactorSignInAsync(TokenOptions.DefaultEmailProvider, verificationCode, false, false); // Replace "Email" with the actual provider name if different

                if (result.Succeeded)
                {
                    IList<string> roles = await VerifyUserRolesAsync(identityUser); // retrieve their roles (at least 1 must exist)
                    await AssignJwtTokensResponse(response, identityUser, roles);
                    response.IsStatus = true;
                }
                else if (result.IsLockedOut) response.Message = "User account locked out";
                else response.Message = "Invalid 2FA code";
            }
            return response;
        }

        /******************************************************
        *         Locking & Unlocking an account              *
        *******************************************************/

        public async Task<LoginRegisterRefreshResponseDto> LockAccountAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"User {userName}'s account has been locked." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                // lock user's account for a longer period (appsetting value in days - user can request unlock email)
                var result = await _userManager.SetLockoutEndDateAsync(identityUser, DateTimeOffset.UtcNow.AddDays(int.Parse(_config.GetSection("SystemDefaults:AdminLocksAccountLifeSpan").Value!)));

                if (!result.Succeeded)
                {
                    response.Message = $"Not able to lock the account of {userName}.";

                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
                else
                {
                    response.IsStatus = true;
                }
            }
            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> RequestUnlockAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"An unlock email request has been sent to user - {userName}." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "An invalid email or the email is not register to your account";
            else
            {
                var unlockToken = await _userManager.GenerateUserTokenAsync(identityUser, TokenOptions.DefaultProvider, TokenOptions.DefaultEmailProvider);
                await SendEmailTaskAsync(identityUser, unlockToken, EmailType.UnlocKAccountRequested);
                response.IsStatus = true; // double up for validating password sent successfully
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> UnlockAccountVerifiedByEmailAsync(string userName, string token)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");
            Guard.Against.Null(token, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"User {userName}'s account has been unlocked." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                // Verify the token
                var isTokenValid = await _userManager.VerifyUserTokenAsync(identityUser,
                                                                           TokenOptions.DefaultProvider,
                                                                           TokenOptions.DefaultEmailProvider,
                                                                           token);
                if (!isTokenValid)
                {
                    response.Message = "Invalid or expired token.";
                }
                else
                {
                    var result = await _userManager.SetLockoutEndDateAsync(identityUser, DateTimeOffset.UtcNow);

                    if (!result.Succeeded)
                    {
                        response.Message = $"Not able to unlock the account of {userName}.";

                        var errors = new StringBuilder();
                        result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                        response.Message = errors.ToString();
                    }
                    else
                    {
                        response.IsStatus = true;
                    }
                }
            }
            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> UnlockAccountVerifiedByAdminAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = $"User {userName}'s account has been unlocked." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                var result = await _userManager.SetLockoutEndDateAsync(identityUser, DateTimeOffset.UtcNow);

                if (!result.Succeeded)
                {
                    response.Message = $"Not able to unlock the account of {userName}.";

                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
                else
                {
                    response.IsStatus = true;
                }
            }
            return response;
        }


        #endregion

        #region Helper Methods
        private async Task AssignJwtTokensResponse(LoginRegisterRefreshResponseDto response, ExtendIdentityUser? identityUser, IList<string> roles)
        {
            response.IsStatus = true;
            response.JwtToken = _jwtTokenService.GenerateJwtToken(identityUser, roles, int.Parse(_config["Jwt:JWT_TOKEN_EXPIRE_MINS"]!));
            response.JwtRefreshToken = _jwtTokenService.GenerateRefreshToken(); // generate a new refresh token the user logs in - improves security
            response.Message = "User logged in successfully";
            response.JwtRefreshTokenExpire = DateTimeOffset.UtcNow.AddDays(int.Parse(_config["Jwt:REFRESH_TOKEN_EXPIRE_DAYS"]!)).UtcDateTime;
            response.JwtTokenExpire = DateTimeOffset.UtcNow.AddMinutes(int.Parse(_config["Jwt:JWT_TOKEN_EXPIRE_MINS"]!)).UtcDateTime;

            // populate identityUser, so that we can update the database table with a new Refresh Token 
            identityUser.RefreshToken = response.JwtRefreshToken;
            identityUser.RefreshTokenExpiry = response.JwtRefreshTokenExpire; // ensure that refresh token expires long after JWT bearer token                        
            identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

            var result = await _userManager.UpdateAsync(identityUser);
            if (!result.Succeeded)
            {
                response.IsStatus = true; // user is still logged in
                var errors = new StringBuilder();
                result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                response.Message = errors.ToString();
            }
            else
            {
                UpdateResponseTokens(response);
            }
        }
        private async Task SendTwoFactorAuthenticationAsync(ExtendIdentityUser identityUser)
        {
            var verificationCode = await _userManager.GenerateTwoFactorTokenAsync(identityUser, "Email");
            //var verificationCode = await _userManager.GenerateTwoFactorTokenAsync(identityUser, TokenOptions.DefaultEmailProvider);
            //var verificationCode = await _userManager.GenerateTwoFactorTokenAsync(identityUser, "Email");

            await SendEmailTaskAsync(identityUser, verificationCode, EmailType.TwoFactorAuthenticationLogin);
        }
        private void CacheRevokedToken(string jwtToken, LoginRegisterRefreshResponseDto response, ClaimsPrincipal principal)
        {
            // store revoked JWT Id in IMemory cache (with sliding timespan)
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtTokenObject = tokenHandler.ReadJwtToken(jwtToken);
            var jti = jwtTokenObject?.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value;

            if (jti == null)
            {
                response.IsStatus = false;
                response.Message = "Invalid JWT to revoke";
            }
            else
            {
                var expiration = jwtTokenObject!.ValidTo - DateTime.UtcNow; // calculate the token's remaining validity period

                // Cache the revoked token's JTI with an sliding (expiry) timespan equal to the token's remaining validity (thus keeping cache clean)
                _memoryCache.Set(jti, true, expiration);

                _logger.LogInformation($"JWT Bearer {jti} was revoked by user {principal.Identity.Name}. Currently {expiration} left before expires");
            }
        }
        private async Task SendEmailTaskAsync(ExtendIdentityUser identityUser, string verificationCode, EmailType emailType)
        {
            string subject = string.Empty;
            string message = string.Empty;
            string actionLink = string.Empty;

            // build up domain\host URL to append confirmation links too
            var domain = $"{_httpContextAccessor.HttpContext?.Request.Scheme}://{_httpContextAccessor.HttpContext?.Request.Host}";

            if (emailType == EmailType.ConfirmationEmail)
            {
                actionLink = $"{domain}{_config["EnvironmentConfirmApiUrl"]}{identityUser.UserName}&token={Uri.EscapeDataString(verificationCode)}";
                subject = "Confirmation Email";
                message = string.Format(ApplicationText.ConfirmEmailTemplate, identityUser.FirstName, actionLink);
            }
            else if (emailType == EmailType.PasswordReset)
            {
                actionLink = $"{domain}{_config["EnvironmentResetPasswordApiUrl"]}{identityUser.UserName}&token={Uri.EscapeDataString(verificationCode)}";
                subject = "Password Reset Request";
                message = string.Format(ApplicationText.ResetPasswordTemplate, identityUser.FirstName, actionLink);                
            }
            else if (emailType == EmailType.TwoFactorAuthenticationLogin)
            {
                actionLink = $"{domain}{_config["Environment2faApiUrl"]}{identityUser.UserName}&code={Uri.EscapeDataString(verificationCode)}";
                subject = "2 Factor Authentication - Login";
                message = string.Format(ApplicationText.TwoFactorAuthenticationTemplate, identityUser.FirstName, actionLink); 
            }
            else if (emailType == EmailType.TwoFactorAuthenticationEnabled)
            {
                subject = "2 Factor Authentication - Enabled";
                message = string.Format(ApplicationText.EnableTwoFactorAuthenticationTemplate, identityUser.FirstName, string.Empty);
            }
            else if (emailType == EmailType.TwoFactorAuthenticationDisabled)
            {
                subject = "2 Factor Authentication - Disabled";
                message = string.Format(ApplicationText.DisableTwoFactorAuthenticationTemplate, identityUser.FirstName, string.Empty);
            }
            else if (emailType == EmailType.UnlocKAccountRequested)
            {
                actionLink = $"{domain}{_config["EnvironmentUnlockVerifyApiUrl"]}{identityUser.UserName}&code={Uri.EscapeDataString(verificationCode)}";
                subject = "2 Factor Authentication - Disabled";
                message = string.Format(ApplicationText.UnlockAccountTemplate, identityUser.FirstName, actionLink);
            }

            await _emailSender.SendEmailAsync(identityUser.Email!, subject, message); // replace ToEmail with your company or private GMail or Yahoo account
        }
        private async Task ValidateUserIdentityAsync(LoginUserDto user, ExtendIdentityUser? identityUser)
        {
            // verify user exists - a BadRequest will be thrown in Global Error Handler (middleware)
            Guard.Against.Null(identityUser, null, "User credentials not valid");

            // verify user's password matches that in the Identity table - a BadRequest will be thrown in Global Error Handler (middleware)
            Guard.Against.Null(await _userManager.CheckPasswordAsync(identityUser, user.Password) ? (bool?)true : null, null, "Invalid credentials entered, please try again.");
        }
        private async Task<IList<string>> VerifyUserRolesAsync(ExtendIdentityUser? identityUser)
        {
            // retrieve roles & verify user has at least 1 role - a BadRequest will be thrown in Global Error Handler (middleware)
            var roles = await _userManager.GetRolesAsync(identityUser); // retrieve role(s) to append to Claims in JWT bearer token
            Guard.Against.Null(roles.Any() ? (bool?)true : null, null, "No roles associated with user - contact Administration.");
            return roles;
        }
        private void UpdateResponseTokens(LoginRegisterRefreshResponseDto clientResponse)
        {
            // reset the cookies in the response
            CookieOptions cookieOptionsJWT, cookieOptionsRefreshJWT;
            GenerateCookieOptions(clientResponse.JwtTokenExpire, clientResponse.JwtRefreshTokenExpire, out cookieOptionsJWT, out cookieOptionsRefreshJWT);

            _httpContextAccessor.HttpContext?.Response.Cookies.Append("jwtToken", clientResponse.JwtToken, cookieOptionsJWT);
            _httpContextAccessor.HttpContext?.Response.Cookies.Append("jwtRefreshToken", clientResponse.JwtRefreshToken, cookieOptionsRefreshJWT);
        }
        private static void GenerateCookieOptions(DateTimeOffset JwtTokenExpire, DateTimeOffset JwtRefreshTokenExpire, out CookieOptions cookieOptionsJWT, out CookieOptions cookieOptionsRefreshJWT)
        {
            // Set the JWT as a HttpOnly cookie
            cookieOptionsJWT = new CookieOptions
            {
                HttpOnly = true,
                IsEssential = true,
                Secure = true, // Ensures the cookie is sent over HTTPS
                SameSite = SameSiteMode.Strict, // Helps mitigate CSRF attacks                        
                Expires = JwtTokenExpire
            };

            // Set the Refresh Token as a HttpOnly cookie
            cookieOptionsRefreshJWT = new CookieOptions
            {
                HttpOnly = true,
                IsEssential = true,
                Secure = true, // Ensures the cookie is sent over HTTPS
                SameSite = SameSiteMode.Strict, // Helps mitigate CSRF attacks                        
                Expires = JwtRefreshTokenExpire

            };
        }
        public async Task<bool> IsUsernameOrEmailTakenAsync(string username, string email)
        {
            var usernameTask = await _userManager.FindByNameAsync(username);

            // check for existing email that is used and not archived
            var emailTask = await _userManager.Users
                                  .Where(u => u.Email == email && u.IsArchived == false)
                                  .FirstOrDefaultAsync();

            var usernameExists = usernameTask != null;
            var emailExists = emailTask != null;

            return usernameExists || emailExists;
        }
       
        #endregion
    }
}
