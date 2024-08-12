﻿using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using ShareMemories.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using ShareMemories.Application.Interfaces;

namespace ShareMemories.Infrastructure.Services
{
    // Controller Action methods
    public class AuthService : IAuthService
    {
        // class variables
        private readonly UserManager<ExtendIdentityUser> _userManager;
        private readonly IConfiguration _config;
        private readonly IJwtTokenService _jwtTokenService;

        public AuthService(UserManager<ExtendIdentityUser> userManager, IConfiguration config, IJwtTokenService jwtTokenService)
        {
            _userManager = userManager;
            _config = config;
            _jwtTokenService = jwtTokenService; 
        }

        #region APIs
        public async Task<LoginRegisterResponseDto> LoginAsync(LoginUserDto user)
        {
            var response = new LoginRegisterResponseDto(); // "IsLoggedIn" will be false by default
            var identityUser = await _userManager.FindByNameAsync(user.UserName);

            // determine if user exists & is valid
            if (identityUser is null || !(await _userManager.CheckPasswordAsync(identityUser, user.Password)))
            {
                response.Message = "User credentials not valid";
                return response;
            }

            var roles = await _userManager.GetRolesAsync(identityUser); // retrieve role(s) to append to Claims in JWT bearer token

            response.IsLoggedIn = true;
            response.JwtToken = _jwtTokenService.GenerateJwtToken(identityUser, roles);
            response.RefreshToken = this.GenerateRefreshTokenString(); // generate a new refresh token the user logs in - improves security
            response.Message = "User logged in successfully";

            // populate identityUser, so that we can update the database
            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.Now.AddDays(1); // ensure that refresh token expires long after JWT bearer token
            identityUser.LastUpdated = DateTime.Now;
            await _userManager.UpdateAsync(identityUser);

            return response;
        }

        public async Task<LoginRegisterResponseDto> RegisterUserAsync(RegisterUserDto user)
        {
            LoginRegisterResponseDto registerResponseDto = new();

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
                LastUpdated = DateTime.Now
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

        public async Task<LoginRegisterResponseDto> RefreshTokenAsync(RefreshTokenModel model)
        {
            var principal = _jwtTokenService.GetPrincipalFromExpiredToken(model.JwtToken);
            //var principal = GetTokenPrincipal(model.JwtToken);

            var response = new LoginRegisterResponseDto();
            if (principal?.Identity?.Name is null)
                return response;

            var identityUser = await _userManager.FindByNameAsync(principal.Identity.Name);

            if (identityUser is null || identityUser.RefreshToken != model.RefreshToken || identityUser.RefreshTokenExpiry < DateTime.Now)
                return response;

            var roles = await _userManager.GetRolesAsync(identityUser); // retrieve role(s) to append to Claims in JWT bearer token

            response.IsLoggedIn = true;
            //response.JwtToken = this.GenerateTokenString(identityUser);
            response.JwtToken = _jwtTokenService.GenerateJwtToken(identityUser, roles);
            //response.RefreshToken = this.GenerateRefreshTokenString();
            response.RefreshToken = _jwtTokenService.GenerateRefreshToken();

            // update AspNetUser DB table with latest details 
            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.Now.AddDays(7); // refresh token should be longer than JWT bearer token
            //identityUser.RefreshTokenExpiry = DateTime.Now.AddSeconds(100); // testing
            await _userManager.UpdateAsync(identityUser);

            return response;
        }

        #endregion

        #region Helper Methods
        private ClaimsPrincipal? GetTokenPrincipal(string token)
        {

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value));

            var validation = new TokenValidationParameters
            {
                IssuerSigningKey = securityKey,
                ValidateLifetime = false,
                ValidateActor = false,
                ValidateIssuer = false,
                ValidateAudience = false,
            };
            return new JwtSecurityTokenHandler().ValidateToken(token, validation, out _);
        }

        private string GenerateRefreshTokenString()
        {
            // this token will eventually be stored in the DB for referencing - and invalidated (in DB) everytime it is used
            var randomNumber = new byte[64];

            using (var numberGenerator = RandomNumberGenerator.Create())
            {
                numberGenerator.GetBytes(randomNumber);
            }

            return Convert.ToBase64String(randomNumber);
        }

        private string GenerateTokenString(ExtendIdentityUser extendIdentityUser)
        {
            // claims' details used in generating the token
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,extendIdentityUser.UserName!),
                new Claim(ClaimTypes.Email,extendIdentityUser.Email!),
                new Claim(ClaimTypes.DateOfBirth,extendIdentityUser.DateOfBirth.ToShortDateString()),

                //new Claim(ClaimTypes.Role,"Admin"), // get role from Principal object (against AD)
            };

            var staticKey = _config.GetSection("Jwt:Key").Value;
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(staticKey));
            var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var securityToken = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(30), // JWT token active for 30 minutes
                signingCredentials: signingCred
                );

            string tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
            return tokenString;
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


        #region Original Blog Code
        //public async Task<IEnumerable<IdentityError>> RegisterUserAsync(LoginUser user)
        //{
        //    var identityUser = new IdentityUser
        //    {
        //        UserName = user.UserName,
        //        Email = user.UserName
        //    };

        //    var result = await _userManager.CreateAsync(identityUser, user.Password);
        //    return result.Errors;
        //}

        // older code
        //public async Task<bool> LoginAsync(LoginUser user)
        //{
        //    var identityUser = await _userManager.FindByEmailAsync(user.UserName);
        //    if (identityUser is null)
        //    {
        //        return false;
        //    }

        //    return await _userManager.CheckPasswordAsync(identityUser, user.Password);
        //}

        //public string GenerateTokenString(LoginUser user)
        //    {
        //        var claims = new List<Claim>
        //        {
        //            new Claim(ClaimTypes.Email,user.UserName),
        //            new Claim(ClaimTypes.Role,"Admin"),
        //        };

        //        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value));

        //        var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);

        //        var securityToken = new JwtSecurityToken(
        //            claims: claims,
        //            expires: DateTime.Now.AddMinutes(1),
        //            issuer: _config.GetSection("Jwt:Issuer").Value,
        //            audience: _config.GetSection("Jwt:Audience").Value,
        //            signingCredentials: signingCred);

        //        string tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
        //        return tokenString;
        //    }
        //}
        #endregion
    }
}
