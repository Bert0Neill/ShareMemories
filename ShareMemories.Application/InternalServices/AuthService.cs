using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.Resources;
using ShareMemories.Domain.Entities;
using ShareMemories.Domain.Enums;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

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
                EmailConfirmed = !_identityOptions.Value.SignIn.RequireConfirmedEmail, // configured in Services.AddIdentity - options.SignIn.RequireConfirmedEmail. Store the opposite to your setting!
                TwoFactorEnabled = bool.Parse(_config.GetSection("SystemDefaults:Is2FAEnabled").Value!) // retrieve form appsettings in API
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
                            registerResponseModel.Message = $"Username: {user.UserName} registered successfully. A confirmation email with a registration token has been sent to {identityUser.Email}, you will need to complete the registration process by opening the Swagger API '/loginGroup/ConfirmRegisteredEmailAsync' and enter your username and token. Check your Spam folder if it isn't in your Inbox.";
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

        public async Task<LoginRegisterRefreshResponseModel> LoginAsync(LoginUserModel user)
        {
            Guard.Against.Null(user, null, "User credentials are not valid");

            int rememberMeExpireDays = int.Parse(_config.GetSection("SystemDefaults:RememberMeLifeSpan").Value!);
            var response = new LoginRegisterRefreshResponseModel(); // "IsStatus" will be false by default
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

            // Check if the account is locked out
            if (await _userManager.IsLockedOutAsync(identityUser))
            {
                response.Message = $"Account is locked. Please wait {_identityOptions.Value.Lockout.DefaultLockoutTimeSpan.TotalMinutes} minutes before trying again.";
                return response;
            }

            IList<string> roles = await VerifyUserRolesAsync(identityUser); // retrieve their roles (at least 1 must exist)

            // try to sign the user in
            await _signInManager.SignOutAsync();

            // Attempt to sign the user in
            SignInResult loginResult = await _signInManager.PasswordSignInAsync(identityUser, user.Password, user.IsPersistent, lockoutOnFailure: true);


            if (loginResult.IsLockedOut || loginResult.IsNotAllowed)
            {
                response.Message = $"Account is either locked (wait {_identityOptions.Value.Lockout.DefaultLockoutTimeSpan} minutes) or you are not allowed to sign-in - contact Administration.";
            }
            else if (loginResult.RequiresTwoFactor) // valid user at this stage - determine if 2FA is enabled and halt login- send 2fa email
            {
                await SendTwoFactorAuthenticationAsync(identityUser!);
                response.IsStatus = true; // this is a valid workflow - user just needs to verify their 2FA code
                response.Message = "Two-factor authentication is enabled on your account. You have been sent an email with a OTP, click on the Swagger API '/2FAGroup/Verify2FactorAuthenticationAsync' and enter your username and the code supplied to complete your login.";
            }
            else if (loginResult.Succeeded)
            {
                // if "remember me" is true from client, extent their login 
                if (user.IsPersistent)
                {
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(rememberMeExpireDays) // Set expiration to days
                    };                 

                    // sign-in again with extended duration
                    await _signInManager.SignInAsync(identityUser, authProperties);
                }                
                await AssignJwtTokensResponse(response, identityUser, roles); // create JWT bearer
            }
            else // failed to login
            {                
                response.Message = "Invalid login attempt. Please check your username and password.";
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseModel> LogoutAsync(string jwtToken)
        {
            Guard.Against.Null(jwtToken, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = "Successfully logged out" }; // default message

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
                    await _signInManager.SignOutAsync(); // this will clear the "AspNetCore.Identity.Application" IsPersistent cookie
                    _httpContextAccessor.HttpContext?.Response.Cookies.Delete("jwtToken");
                    _httpContextAccessor.HttpContext?.Response.Cookies.Delete("jwtRefreshToken");
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseModel> VerifyEmailConfirmationAsync(string userName, string token)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");
            Guard.Against.Null(token, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = "Email confirmation successful, you can now login." }; // default message

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

        public async Task<LoginRegisterRefreshResponseModel> RequestConfirmationEmailAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = $"A new confirmation email has been sent - check your Spam folder." }; // default message

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
        
        public async Task<LoginRegisterRefreshResponseModel> UpdateUserDetailsAsync(string jwtToken, RegisterUserModel userUpdateDetails)
        {
            Guard.Against.Null(userUpdateDetails, null, "User details are not valid");
            
            LoginRegisterRefreshResponseModel registerResponseModel = new() { Message = $"Username: {userUpdateDetails.UserName} registered successfully. You can now login" };

            var claimsPrincipal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

            // not able to retrieve user from Jwt bearer token
            if (claimsPrincipal?.Identity?.Name is null)
            {
                registerResponseModel.IsStatus = false;
                registerResponseModel.Message = "Jwt Bearer is not valid, during update process";
            }
            else
            {
                var identityUser = await _userManager.FindByNameAsync(claimsPrincipal.Identity.Name); // retrieve user principal
                var roles = await _userManager.GetRolesAsync(identityUser);

                if (identityUser is null)
                {
                    registerResponseModel.IsStatus = false;
                    registerResponseModel.Message = $"User '{claimsPrincipal.Identity.Name}' not found during details update";
                    return registerResponseModel;
                }

                // verify that email is not in use already by another account
                if (!String.IsNullOrEmpty(userUpdateDetails.Email))
                {
                    var user = await _userManager.FindByEmailAsync(userUpdateDetails.Email);
                    if (user is not null)
                    {
                        if (user.UserName != claimsPrincipal.Identity.Name)
                        {
                            registerResponseModel.IsStatus = false;
                            registerResponseModel.Message = "Email has already been assigned to another user";
                            return registerResponseModel;
                        }
                    }
                }

                // update user details (that have been supplied)
                identityUser.Email = userUpdateDetails.Email != string.Empty ? userUpdateDetails.Email : identityUser.Email;
                identityUser.PhoneNumber = userUpdateDetails.PhoneNumber != string.Empty ? userUpdateDetails.PhoneNumber : identityUser.PhoneNumber;
                identityUser.FirstName = userUpdateDetails.FirstName != string.Empty ? userUpdateDetails.FirstName : identityUser.FirstName;
                identityUser.LastName = userUpdateDetails.LastName != string.Empty ? userUpdateDetails.LastName : identityUser.LastName;
                identityUser.DateOfBirth = userUpdateDetails.DateOfBirth != default(DateOnly)  ? userUpdateDetails.DateOfBirth  : identityUser.DateOfBirth;

                // create new tokens for clients browser based on their updated details
                registerResponseModel.JwtToken = _jwtTokenService.GenerateJwtToken(identityUser, roles, int.Parse(_config["Jwt:JWT_TOKEN_EXPIRE_MINS"]!));
                registerResponseModel.JwtRefreshToken = _jwtTokenService.GenerateRefreshToken();
                registerResponseModel.JwtRefreshTokenExpire = DateTimeOffset.UtcNow.AddDays(int.Parse(_config["Jwt:REFRESH_TOKEN_EXPIRE_DAYS"]!)).UtcDateTime;
                registerResponseModel.JwtTokenExpire = DateTimeOffset.UtcNow.AddMinutes(int.Parse(_config["Jwt:JWT_TOKEN_EXPIRE_MINS"]!)).UtcDateTime;

                // update AspNetUser DB table with latest details 
                identityUser.RefreshToken = registerResponseModel.JwtRefreshToken;
                identityUser.RefreshTokenExpiry = registerResponseModel.JwtRefreshTokenExpire; // refresh token should be longer than JWT bearer token
                identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

                var result = await _userManager.UpdateAsync(identityUser); // update database

                // handle a database fail
                if (!result.Succeeded)
                {
                    registerResponseModel.IsStatus = false;
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"{err.Description}")); // build up a string of faults
                    registerResponseModel.Message = errors.ToString();
                }
                else // success
                {
                    // notify user of update (return new JWT Bearer Token and refresh Tokens)
                    registerResponseModel.IsStatus = true;
                    registerResponseModel.Message = "User details have been updated";

                    // notify user that details have been updated
                    await SendEmailTaskAsync(identityUser, string.Empty, EmailType.DetailsUpdated);
                }
            }

            return registerResponseModel;
        }

        public async Task<LoginRegisterRefreshResponseModel> ViewUserDetailsAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = $"Details for {userName}" }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                response.IsStatus = true;

                response.Message += Environment.NewLine;
                response.Message += $"User ID: {identityUser.Id}\n";
                response.Message += $"Username: {identityUser.UserName}\n";
                response.Message += $"Email: {identityUser.Email}\n";
                response.Message += $"Phone: {identityUser.PhoneNumber}\n";
                response.Message += $"First Name: {identityUser.FirstName}\n";
                response.Message += $"Last Name: {identityUser.LastName}\n";
                response.Message += $"DOB: {identityUser.DateOfBirth}\n";

                var roles = await _userManager.GetRolesAsync(identityUser);
                response.Message += "Roles: " + string.Join(", ", roles);
            }

            return response;
        }
        
        /******************************************************
        *               JWT Refresh & Revoke                  *
        *******************************************************/
        public async Task<LoginRegisterRefreshResponseModel> RefreshTokenAsync(string jwtToken, string refreshToken)
        {
            var response = new LoginRegisterRefreshResponseModel();

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

        public async Task<LoginRegisterRefreshResponseModel> RevokeTokenLogoutAsync(string jwtToken)
        {
            Guard.Against.Null(jwtToken, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = "Successfully revoked JWT token", IsStatus = true }; // default message

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

        public async Task<LoginRegisterRefreshResponseModel> VerifyPasswordResetAsync(string jwtToken, string token, string newPassword, string oldPassword)
        {
            Guard.Against.Null(jwtToken, null, "JWT Bearer is not valid");
            Guard.Against.Null(token, null, "Token is not valid");
            Guard.Against.Null(newPassword, null, "Password is not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message= "Password was reset successfully." }; // default message

            var claimsPrincipal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

            // not able to retrieve user from Jwt bearer token
            if (claimsPrincipal?.Identity?.Name is null)
            {
                response.Message = "Jwt Bearer is not valid, during password request";
                return response;
            }

            var identityUser = await _userManager.FindByNameAsync(claimsPrincipal.Identity.Name);
            if (identityUser == null) response.Message = "Invalid credentials or token";
            else
            {
                // Verify the old password
                var passwordCheck = await _userManager.CheckPasswordAsync(identityUser, oldPassword);
                if (!passwordCheck)
                {
                    response.Message = "Old password is incorrect";
                    return response;
                }

                var result = await _userManager.ResetPasswordAsync(identityUser, token, newPassword);

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

        public async Task<LoginRegisterRefreshResponseModel> RequestPasswordResetAsync(string jwtToken)
        {
            var response = new LoginRegisterRefreshResponseModel();

            var claimsPrincipal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

            // not able to retrieve user from Jwt bearer token
            if (claimsPrincipal?.Identity?.Name is null)
            {                
                response.Message = "Jwt Bearer is not valid, during password request";
                return response;
            }

            response.Message = $"A password reset request has been sent to user - {claimsPrincipal.Identity.Name}."; // default message

            var identityUser = await _userManager.FindByNameAsync(claimsPrincipal.Identity.Name);

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
        public async Task<LoginRegisterRefreshResponseModel> Enable2FactorAuthenticationForUserAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = $"User {userName} has had their 2FA enabled." }; // default message

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

        public async Task<LoginRegisterRefreshResponseModel> Disable2FactorAuthenticationForUserAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = $"User {userName} has had their 2FA disabled." }; // default message

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

        public async Task<LoginRegisterRefreshResponseModel> Verify2FactorAuthenticationAsync(string userName, string verificationCode)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");
            Guard.Against.Null(verificationCode, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = "2FA verification successful. You have been verified, you can now call the (secure) API's" }; // default message

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

        public async Task<LoginRegisterRefreshResponseModel> Request2FACodeAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseModel(); // "IsStatus" will be false by default
            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser is null)
            {
                response.Message = $"Credentials are not valid";
                return response;
            }
            
            await SendTwoFactorAuthenticationAsync(identityUser!);
            response.Message = "Two-factor authentication is enabled on your account. You have been sent an email with a OTP, click on the Swagger API '/2FAGroup/Verify2FactorAuthenticationAsync' and enter your username and the code supplied to complete your login.";

            return response;
        }


        /******************************************************
        *         Locking & Unlocking an account              *
        *******************************************************/
        public async Task<LoginRegisterRefreshResponseModel> LockAccountAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            int adminLockoutDuration = int.Parse(_config.GetSection("SystemDefaults:AdminLocksAccountLifeSpan").Value); // locked for days

            var response = new LoginRegisterRefreshResponseModel() { Message = $"User {userName}'s account has been locked." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "Invalid credentials supplied.";
            else
            {
                // lock user's account for a longer period (appsetting value in days - user can request unlock email)
                var result = await _userManager.SetLockoutEndDateAsync(identityUser, DateTimeOffset.UtcNow.AddDays(adminLockoutDuration));

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

        public async Task<LoginRegisterRefreshResponseModel> RequestUnlockAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = $"An unlock email request has been sent to user - {userName}." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "An invalid email or the email is not register to your account";
            else
            {
                // Generate an unlock token for the user
                var unlockToken = await _userManager.GenerateUserTokenAsync(identityUser, TokenOptions.DefaultProvider, TokenOptions.DefaultEmailProvider);
                
                await SendEmailTaskAsync(identityUser, unlockToken, EmailType.UnlocKAccountRequested);
                response.IsStatus = true; // double up for validating password sent successfully
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseModel> UnlockAccountVerifiedByEmailAsync(string userName, string token)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");
            Guard.Against.Null(token, null, "Token is not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = $"User {userName}'s account has been unlocked." }; // default message

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

        public async Task<LoginRegisterRefreshResponseModel> UnlockAccountVerifiedByAdminAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials are not valid");

            var response = new LoginRegisterRefreshResponseModel() { Message = $"User {userName}'s account has been unlocked." }; // default message

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
        private async Task AssignJwtTokensResponse(LoginRegisterRefreshResponseModel response, ExtendIdentityUser? identityUser, IList<string> roles)
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
            var verificationCode = await _userManager.GenerateTwoFactorTokenAsync(identityUser, TokenOptions.DefaultEmailProvider);            

            await SendEmailTaskAsync(identityUser, verificationCode, EmailType.TwoFactorAuthenticationLogin);
        }
        private void CacheRevokedToken(string jwtToken, LoginRegisterRefreshResponseModel response, ClaimsPrincipal principal)
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
        private async Task<IList<string>> VerifyUserRolesAsync(ExtendIdentityUser? identityUser)
        {
            // retrieve roles & verify user has at least 1 role - a BadRequest will be thrown in Global Error Handler (middleware)
            var roles = await _userManager.GetRolesAsync(identityUser); // retrieve role(s) to append to Claims in JWT bearer token
            Guard.Against.Null(roles.Any() ? (bool?)true : null, null, "No roles associated with user - contact Administration.");
            return roles;
        }
        private void UpdateResponseTokens(LoginRegisterRefreshResponseModel clientResponse)
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
        private async Task SendEmailTaskAsync(ExtendIdentityUser identityUser, string verificationCode, EmailType emailType)
        {
            string subject = string.Empty;
            string message = string.Empty;
            string actionLink = string.Empty;
            string token = Uri.EscapeDataString(verificationCode);
            string domain = $"{_httpContextAccessor.HttpContext?.Request.Scheme}://{_httpContextAccessor.HttpContext?.Request.Host}";

            switch (emailType)
            {
                case EmailType.ConfirmationEmail:
                    actionLink = $"{domain}{_config["EnvironmentConfirmApiUrl"]}{identityUser.UserName}&token={token}";
                    subject = "Confirmation Email";
                    message = string.Format(ApplicationText.ConfirmEmailTemplate, identityUser.FirstName, actionLink);
                    break;

                case EmailType.PasswordReset:
                    subject = "Password Reset Request";
                    message = string.Format(ApplicationText.ResetPasswordTemplate, identityUser.FirstName, token);
                    break;

                case EmailType.TwoFactorAuthenticationLogin:
                    subject = "2 Factor Authentication - Login";
                    message = string.Format(ApplicationText.TwoFactorAuthenticationTemplate, identityUser.FirstName, token);
                    break;

                case EmailType.TwoFactorAuthenticationEnabled:
                    subject = "2 Factor Authentication - Enabled";
                    message = string.Format(ApplicationText.EnableTwoFactorAuthenticationTemplate, identityUser.FirstName, string.Empty);
                    break;

                case EmailType.TwoFactorAuthenticationDisabled:
                    subject = "2 Factor Authentication - Disabled";
                    message = string.Format(ApplicationText.DisableTwoFactorAuthenticationTemplate, identityUser.FirstName, string.Empty);
                    break;

                case EmailType.UnlocKAccountRequested:
                    actionLink = $"{domain}{_config["EnvironmentUnlockVerifyApiUrl"]}{identityUser.UserName}&token={token}";
                    subject = "Request To Unlock Your Account";
                    message = string.Format(ApplicationText.UnlockAccountTemplate, identityUser.FirstName, actionLink);
                    break;

                case EmailType.DetailsUpdated:
                    subject = "User Details Updated";
                    message = string.Format(ApplicationText.UserDetailsUpdatedTemplate, identityUser.FirstName);
                    break;
            }

            await _emailSender.SendEmailAsync(identityUser.Email!, subject, message);
        }


        #endregion
    }
}
