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

namespace ShareMemories.Infrastructure.Services
{
    // Controller Action methods
    public class AuthService : IAuthService
    {
        // class variables
        private readonly UserManager<ExtendIdentityUser> _userManager;
        private readonly IConfiguration _config;

        public AuthService(UserManager<ExtendIdentityUser> userManager, IConfiguration config)
        {
            _userManager = userManager;
            _config = config;
        }

        #region APIs
        public async Task<IdentityResult> RegisterUserAsync(RegisterUserDto user)
        {
            var identityUser = new ExtendIdentityUser
            {
                UserName = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                DateOfBirth = user.DateOfBirth

            };

            var result = await _userManager.CreateAsync(identityUser, user.Password);
            return result;
        }

        public async Task<LoginResponseDto> LoginAsync(LoginUserDto user)
        {
            var response = new LoginResponseDto(); // "IsLoggedIn" will be false by default
            var identityUser = await _userManager.FindByEmailAsync(user.Email);

            // determine if user exists & is valid
            if (identityUser is null || !(await _userManager.CheckPasswordAsync(identityUser, user.Password)))
            {
                response.Message = "User credentials not valid";
                return response; 
            }

            response.IsLoggedIn = true;
            response.JwtToken = this.GenerateTokenString(identityUser);
            //response.JwtToken = this.GenerateTokenString(identityUser.Email);
            response.RefreshToken = this.GenerateRefreshTokenString();
            response.Message = "User logged in successfully";

            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.Now.AddDays(1); // default to 1 day
            await _userManager.UpdateAsync(identityUser);

            return response;
        }

        public async Task<LoginResponseDto> RefreshTokenAsync(RefreshTokenModel model)
        {
            var principal = GetTokenPrincipal(model.JwtToken);

            var response = new LoginResponseDto();
            if (principal?.Identity?.Name is null)
                return response;

            var identityUser = await _userManager.FindByNameAsync(principal.Identity.Name);

            if (identityUser is null || identityUser.RefreshToken != model.RefreshToken || identityUser.RefreshTokenExpiry < DateTime.Now)
                return response;

            response.IsLoggedIn = true;
            response.JwtToken = this.GenerateTokenString(identityUser);
            //response.JwtToken = this.GenerateTokenString(identityUser.Email);
            response.RefreshToken = this.GenerateRefreshTokenString();

            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.Now.AddDays(1); // refresh token - default to 1 day (JWT default to 30 minutes or less)
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
