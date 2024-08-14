using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using ShareMemories.Application.Interfaces;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Interfaces;
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

        private bool _isRefreshing = false;
        private const int REFRESH_TOKEN_EXPIRE_DAYS = 10;
        private const int JWT_TOKEN_EXPIRE_MINS = 30;        
        public AuthService(UserManager<ExtendIdentityUser> userManager, IConfiguration config, IJwtTokenService jwtTokenService, SignInManager<ExtendIdentityUser> signInManager, IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _config = config;
            _jwtTokenService = jwtTokenService;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
        }

        #region APIs
        public async Task<LoginRegisterRefreshResponseDto> LoginAsync(LoginUserDto user)
        {
            var response = new LoginRegisterRefreshResponseDto(); // "IsLoggedIn" will be false by default
            var identityUser = await _userManager.FindByNameAsync(user.UserName);

            // determine if user exists & passwords match
            if (identityUser is null || !(await _userManager.CheckPasswordAsync(identityUser, user.Password)))
            {
                response.Message = "User credentials not valid";
                return response;
            }

            var roles = await _userManager.GetRolesAsync(identityUser); // retrieve role(s) to append to Claims in JWT bearer token

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

            await _userManager.UpdateAsync(identityUser);

            UpdateResponseTokens(response);

            return response;
        }     

        public async Task<LoginRegisterRefreshResponseDto> RegisterUserAsync(RegisterUserDto user)
        {
            LoginRegisterRefreshResponseDto registerResponseDto = new();

            // verify that Username and\or email have not already been registered
            if (await IsUsernameOrEmailTakenAsync(user.UserName, user.Email))
            {
                registerResponseDto.Message = $"Username {user.UserName} or Email {user.Email}, already exists within the system";
                return registerResponseDto;
            }

            // add these details to the AspNetUser table
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

            registerResponseDto.IsLoggedIn = true; // allow checks below to modify logged in status

            if (result.Errors.Any())
            {
                var errors = new StringBuilder();
                result.Errors.ToList().ForEach(err => errors.AppendLine($"• {err.Description}")); // build up a string of faults
                registerResponseDto.Message = errors.ToString();
                registerResponseDto.IsLoggedIn = false; // user not successfully registered
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
                    registerResponseDto.IsLoggedIn = false; // user not successfully registered
                }                
                else // success registering user & role
                    registerResponseDto.Message = $"Username: {user.UserName} registered successfully, you can now log in.";
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

                    await _userManager.UpdateAsync(identityUser);

                    UpdateResponseTokens(response);

                    //// reset the cookies in the response
                    //CookieOptions cookieOptionsJWT, cookieOptionsRefreshJWT;
                    //GenerateCookieOptions(response.JwtTokenExpire, response.JwtRefreshTokenExpire, out cookieOptionsJWT, out cookieOptionsRefreshJWT);
                    //_httpContextAccessor.HttpContext.Response.Cookies.Append("jwtToken", response.JwtToken, cookieOptionsJWT);
                    //_httpContextAccessor.HttpContext.Response.Cookies.Append("jwtRefreshToken", response.JwtRefreshToken, cookieOptionsRefreshJWT);

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
                    response.Message = "Failed to delete Refresh Token, during logout process";
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
                    response.Message = "Failed to revoke refresh token, during revoke process";
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

        #endregion

        #region Helper Methods

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
