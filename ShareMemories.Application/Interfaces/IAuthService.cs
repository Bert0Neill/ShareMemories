﻿
using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Identity;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Enums;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IAuthService
    {
        Task<LoginRegisterRefreshResponseDto> LoginAsync(LoginUserDto user);
        Task<LoginRegisterRefreshResponseDto> RefreshTokenAsync(string jwtToken, string refreshToken);
        Task<LoginRegisterRefreshResponseDto> RegisterUserAsync(RegisterUserDto user);
        Task<LoginRegisterRefreshResponseDto> LogoutAsync(string jwtToken);
        Task<LoginRegisterRefreshResponseDto> RevokeTokenLogoutAsync(string jwtToken);
        Task<LoginRegisterRefreshResponseDto> VerifyEmailConfirmationAsync(string userName, string token);
        Task<LoginRegisterRefreshResponseDto> RequestPasswordResetAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> VerifyPasswordResetAsync(string userName, string token, string password);
        Task<LoginRegisterRefreshResponseDto> RequestConfirmationEmailAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> Verify2faAsync(string userName, string verificationCode);
        Task<LoginRegisterRefreshResponseDto> Disable2FactorAuthenticationForUserAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> Enable2FactorAuthenticationForUserAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> UnlockAccountAsync(string userName, string token);
        Task<LoginRegisterRefreshResponseDto> LockAccountAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> RequestUnlockAsync(string userName);
    }
}