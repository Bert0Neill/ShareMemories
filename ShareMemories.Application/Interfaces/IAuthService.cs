
using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Identity;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Enums;
using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IAuthService
    {
        Task<LoginRegisterRefreshResponseDto> LoginAsync(LoginUserDto user);
        Task<LoginRegisterRefreshResponseDto> RefreshTokenAsync(string jwtToken, string refreshToken);
        Task<LoginRegisterRefreshResponseDto> RegisterUserAsync(RegisterUserModel user);
        Task<LoginRegisterRefreshResponseDto> LogoutAsync(string jwtToken);
        Task<LoginRegisterRefreshResponseDto> RevokeTokenLogoutAsync(string jwtToken);
        Task<LoginRegisterRefreshResponseDto> VerifyEmailConfirmationAsync(string userName, string token);
        Task<LoginRegisterRefreshResponseDto> RequestPasswordResetAsync(string jwtToken);        
        Task<LoginRegisterRefreshResponseDto> VerifyPasswordResetAsync(string jwtToken, string token, string newPassword, string oldPassword);
        Task<LoginRegisterRefreshResponseDto> RequestConfirmationEmailAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> Verify2FactorAuthenticationAsync(string userName, string verificationCode);
        Task<LoginRegisterRefreshResponseDto> Disable2FactorAuthenticationForUserAsync(string userName);        
        Task<LoginRegisterRefreshResponseDto> Request2FACodeAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> Enable2FactorAuthenticationForUserAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> UnlockAccountVerifiedByEmailAsync(string userName, string token);
        Task<LoginRegisterRefreshResponseDto> UnlockAccountVerifiedByAdminAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> LockAccountAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> RequestUnlockAsync(string userName);
        Task<LoginRegisterRefreshResponseDto> UpdateUserDetailsAsync(string jwtToken, UpdateUserDetailsDto userUpdateDetails);
        Task<LoginRegisterRefreshResponseDto> ViewUserDetailsAsync(string userName);
    }
}