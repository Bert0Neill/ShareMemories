using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using ShareMemories.Application.Interfaces;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Interfaces;
using System;
using System.Text;

namespace ShareMemories.Infrastructure.Services
{
    // Controller Action methods
    public class AuthService : IAuthService
    {
        // class variables
        private readonly UserManager<ExtendIdentityUser> _userManager;
        private readonly SignInManager<ExtendIdentityUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailSender _emailSender;

        private bool _isRefreshing = false;
        private const int REFRESH_TOKEN_EXPIRE_DAYS = 10;
        private const int JWT_TOKEN_EXPIRE_MINS = 30;        
        public AuthService(UserManager<ExtendIdentityUser> userManager, IConfiguration config, IJwtTokenService jwtTokenService, SignInManager<ExtendIdentityUser> signInManager, IHttpContextAccessor httpContextAccessor, IEmailSender emailSender)
        {
            _userManager = userManager;
            _config = config;
            _jwtTokenService = jwtTokenService;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _emailSender = emailSender;
        }

        #region APIs
        public async Task<LoginRegisterRefreshResponseDto> LoginAsync(LoginUserDto user)
        {
            Guard.Against.Null(user, null, "User credentials not valid");

            var response = new LoginRegisterRefreshResponseDto(); // "IsLoggedIn" will be false by default
            var identityUser = await _userManager.FindByNameAsync(user.UserName);

            IList<string> roles = await VerifyUserIdentityAsync(user, identityUser); // checks to verify a valid user - a BadRequest is thrown otherwise

            response.IsLoggedIn = true;
            response.JwtToken = _jwtTokenService.GenerateJwtToken(identityUser, roles, JWT_TOKEN_EXPIRE_MINS);
            response.JwtRefreshToken = _jwtTokenService.GenerateRefreshToken(); // generate a new refresh token the user logs in - improves security
            response.Message = "User logged in successfully";
            response.JwtRefreshTokenExpire = DateTimeOffset.UtcNow.AddDays(REFRESH_TOKEN_EXPIRE_DAYS).UtcDateTime;
            response.JwtTokenExpire = DateTimeOffset.UtcNow.AddMinutes(JWT_TOKEN_EXPIRE_MINS).UtcDateTime;

            // populate identityUser, so that we can update the database table with a new Refresh Token 
            identityUser.RefreshToken = response.JwtRefreshToken;
            identityUser.RefreshTokenExpiry = response.JwtRefreshTokenExpire; // ensure that refresh token expires long after JWT bearer token                        
            identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

            var result = await _userManager.UpdateAsync(identityUser);
            if (!result.Succeeded)
            {
                response.IsLoggedIn = true; // user is still logged in
                var errors = new StringBuilder();
                result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                response.Message = errors.ToString();
            }
            else UpdateResponseTokens(response);

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> RegisterUserAsync(RegisterUserDto user)
        {
            Guard.Against.Null(user, null, "User credentials not valid");

            LoginRegisterRefreshResponseDto registerResponseDto = new();

            // verify that Username and\or email have not already been registered
            if (await IsUsernameOrEmailTakenAsync(user.UserName, user.Email))
            {
                registerResponseDto.Message = $"Username {user.UserName} or Email {user.Email}, already exists within the system";
                return registerResponseDto;
            }

            // add these details to a new AspNetUser table instance
            var identityUser = new ExtendIdentityUser
            {
                UserName = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                DateOfBirth = user.DateOfBirth,
                LastUpdated = DateTimeOffset.UtcNow.UtcDateTime               
            };

            var result = await _userManager.CreateAsync(identityUser, user.Password);

            if (result.Errors.Any())
            {
                var errors = new StringBuilder();
                result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                registerResponseDto.Message = errors.ToString();
            }
            else // success - assign default role
            {
                // assign a default role (USER) to the user
                var roleAssignResult = await _userManager.AddToRoleAsync(identityUser, "User"); // Replace "User" with the desired role

                if (roleAssignResult.Errors.Any())
                {
                    var roleErrors = new StringBuilder();
                    roleAssignResult.Errors.ToList().ForEach(err => roleErrors.AppendLine($"• {err.Description}"));
                    registerResponseDto.Message = $"Username: {user.UserName} registered, but there was an issue assigning roles: {roleErrors}";
                }
                else // success registering user & role
                {
                    string verificationCode = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser); // generate token to be used in URL
                    await SendEmailTaskAsync(identityUser, verificationCode, true);

                    registerResponseDto.Message = $"Username: {user.UserName} registered successfully. A confirmation email has been sent to {identityUser.Email}, you will need to click the link within the email to complete the registration. Check your Spam folder if it isn't in your Inbox.";
                    registerResponseDto.IsLoggedIn = true; // doubling up the IsLoggedIn property to indicate if user was successfully registered or not
                }
            }

            return registerResponseDto;
        }      

        public async Task<LoginRegisterRefreshResponseDto> RefreshTokenAsync(string jwtToken, string refreshToken)
        {
            var response = new LoginRegisterRefreshResponseDto();

            try
            {
                if (!_isRefreshing) // stop user refresh saturation
                {
                    _isRefreshing = true;
                    
                    var principal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

                    // not able to retrieve user from Jwt token
                    if (principal?.Identity?.Name is null)
                    {
                        await LogoutAsync(jwtToken); // call logout
                        response.Message = "Jwt Bearer not valid";
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

                    response.IsLoggedIn = true;
                    response.JwtToken = _jwtTokenService.GenerateJwtToken(identityUser, roles, JWT_TOKEN_EXPIRE_MINS);
                    response.JwtRefreshToken = _jwtTokenService.GenerateRefreshToken();

                    // update AspNetUser DB table with latest details 
                    identityUser.RefreshToken = response.JwtRefreshToken;
                    identityUser.RefreshTokenExpiry = DateTimeOffset.UtcNow.AddDays(REFRESH_TOKEN_EXPIRE_DAYS).UtcDateTime; // refresh token should be longer than JWT bearer token
                    identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

                    var result = await _userManager.UpdateAsync(identityUser);
                    if (!result.Succeeded)
                    {
                        response.IsLoggedIn = true; // user is still logged in
                        var errors = new StringBuilder();
                        result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                        response.Message = errors.ToString();
                    }
                    else UpdateResponseTokens(response);

                    return response;
                }
            }
            finally { _isRefreshing = false; }

            // Return a response in case the token is already refreshing
            response.Message = "Token is already refreshing.";
            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> LogoutAsync(string jwtToken)
        {
            Guard.Against.Null(jwtToken, null, "Token not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "Successfully logged out" }; // default message

            var principal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

            // not able to retrieve user from Jwt bearer token
            if (principal?.Identity?.Name is null)
            {
                response.IsLoggedIn = true; // user is still logged in
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
                    response.IsLoggedIn = true; // user is still logged in
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
                else
                {
                    // remove cookies form response to client
                    await _signInManager.SignOutAsync();
                    _httpContextAccessor.HttpContext.Response.Cookies.Delete("jwtToken");
                    _httpContextAccessor.HttpContext.Response.Cookies.Delete("jwtRefreshToken");
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> RevokeRefreshTokenAsync(string jwtToken)
        {
            Guard.Against.Null(jwtToken, null, "Token not valid");
            
            var response = new LoginRegisterRefreshResponseDto() { Message = "Successfully revoked refresh token" }; // default message

            var principal = _jwtTokenService.GetPrincipalFromExpiredToken(jwtToken);

            // not able to retrieve user from Jwt bearer token
            if (principal?.Identity?.Name is null)
            {
                response.IsRefreshRevoked = false; 
                response.Message = "Jwt Bearer not valid, during revoke process";
            }
            else
            {
                var identityUser = await _userManager.FindByNameAsync(principal.Identity.Name); // retrieve user principal

                if (identityUser is null)
                {
                    response.IsRefreshRevoked = false;
                    response.Message = $"User '{principal.Identity.Name}' not found during refresh token revoke";
                    return response;
                }

                // clear the refresh token
                identityUser!.RefreshToken = null;
                identityUser.RefreshTokenExpiry = null;
                identityUser.LastUpdated = DateTimeOffset.UtcNow.UtcDateTime;

                var result = await _userManager.UpdateAsync(identityUser); // update database

                // handle a database fail
                if (!result.Succeeded)
                {
                    response.IsRefreshRevoked = false;
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
                else // success
                {
                    // sign out & remove cookies from response to client
                    await _signInManager.SignOutAsync();
                    _httpContextAccessor.HttpContext.Response.Cookies.Delete("jwtToken");
                    _httpContextAccessor.HttpContext.Response.Cookies.Delete("jwtRefreshToken");
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> VerifyEmailConfirmationAsync(string userName, string token)
        {
            Guard.Against.Null(userName, null, "User credentials not valid");
            Guard.Against.Null(token, null, "Token not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "Email confirmation successful, you can now login." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);
            if (identityUser == null) response.Message = "Invalid credentials or token";            
            else
            {
                var result = await _userManager.ConfirmEmailAsync(identityUser, token);

                if (result.Succeeded) response.IsLoggedIn = true;
                else
                {
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> RequestPasswordResetAsync(string userName)
        {
            Guard.Against.Null(userName, null, "User credentials not valid");            

            var response = new LoginRegisterRefreshResponseDto() { Message = $"A password reset request has been sent to user - {userName}." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);

            if (identityUser == null) response.Message = "An invalid email or the email is not register to your account";
            else
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser);
                await SendEmailTaskAsync(identityUser, token, false);
                response.IsLoggedIn = true; // double up for validating password sent successfully
            }

            return response;
        }

        public async Task<LoginRegisterRefreshResponseDto> VerifyPasswordResetAsync(string userName, string token, string password)
        {
            Guard.Against.Null(userName, null, "User credentials not valid");
            Guard.Against.Null(token, null, "Token not valid");
            Guard.Against.Null(password, null, "Password not valid");

            var response = new LoginRegisterRefreshResponseDto() { Message = "Password was reset successfully." }; // default message

            var identityUser = await _userManager.FindByNameAsync(userName);
            if (identityUser == null) response.Message = "Invalid credentials or token";
            else
            {
                var result = await _userManager.ResetPasswordAsync(identityUser, token, password);

                if (result.Succeeded) response.IsLoggedIn = true;
                else
                {
                    var errors = new StringBuilder();
                    result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                    response.Message = errors.ToString();
                }
            }

            return response;
        }

        #endregion

        #region Helper Methods
        private async Task SendEmailTaskAsync(ExtendIdentityUser identityUser, string verificationCode, bool isConfirmEmail = true)
        {
            string subject;
            string message;
            string actionLink;

            if (isConfirmEmail)
            {
                actionLink = $"{_config["EnvironmentConfirmApiUrl"]}{identityUser.UserName}&token={Uri.EscapeDataString(verificationCode)}";

                // Build up Email Confirmation
                subject = "Confirmation Email";
                message = $@"
                    Hello {identityUser.FirstName}

                    Thank you for registering. Please confirm your email by clicking the link below:
                    
                    Confirm email link: {actionLink}

                    If you did not register for this site, please ignore this email.

                    Thanking you
                    O'Neill Says!";
            }
            else
            {
                actionLink = $"{_config["EnvironmentResetPasswordApiUrl"]}{identityUser.UserName}&token={Uri.EscapeDataString(verificationCode)}";

                // Build up Email Confirmation
                subject = "Password Reset Request";
                message = $@"
                    Hello {identityUser.FirstName}

                    We received a request to reset your password. Click the link below to reset it:
                    
                    Reset password link: {actionLink}

                    If you did not request a password reset, please ignore this email.

                    Thanking you
                    O'Neill Says!";
            }

            await _emailSender.SendEmailAsync(identityUser.Email, subject, message); // replace ToEmail with your company or private GMail or Yahoo account
        }
        private async Task<IList<string>> VerifyUserIdentityAsync(LoginUserDto user, ExtendIdentityUser? identityUser)
        {
            // verify user exists - a BadRequest will be thrown in Global Error Handler (middleware)
            Guard.Against.Null(identityUser, null, "User credentials not valid");

            // verify user confirmed email address - a BadRequest will be thrown in Global Error Handler (middleware)
            Guard.Against.Null(await _userManager.IsEmailConfirmedAsync(identityUser) ? (bool?)true : null, null, "User has not yet confirmed their email address. Check your Spam folder.");

            // verify user's password matches that in the Identity table - a BadRequest will be thrown in Global Error Handler (middleware)
            Guard.Against.Null(await _userManager.CheckPasswordAsync(identityUser, user.Password) ? (bool?)true : null, null, "Invalid credentials entered, please try again.");

            // retrieve roles & verify user has at least 1 role - a BadRequest will be thrown in Global Error Handler (middleware)
            var roles = await _userManager.GetRolesAsync(identityUser); // retrieve role(s) to append to Claims in JWT bearer token
            Guard.Against.Null(roles.Any() ? (bool?)true : null, null, "No roles associated with user - contact Administration.");
            return roles;
        }
        private void UpdateResponseTokens(LoginRegisterRefreshResponseDto response)
        {
            // reset the cookies in the response
            CookieOptions cookieOptionsJWT, cookieOptionsRefreshJWT;
            GenerateCookieOptions(response.JwtTokenExpire, response.JwtRefreshTokenExpire, out cookieOptionsJWT, out cookieOptionsRefreshJWT);
            _httpContextAccessor.HttpContext.Response.Cookies.Append("jwtToken", response.JwtToken, cookieOptionsJWT);
            _httpContextAccessor.HttpContext.Response.Cookies.Append("jwtRefreshToken", response.JwtRefreshToken, cookieOptionsRefreshJWT);
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
