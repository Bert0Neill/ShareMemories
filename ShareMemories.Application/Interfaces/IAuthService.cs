using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IAuthService
    {
        Task<LoginRegisterRefreshResponseModel> LoginAsync(LoginUserModel user);
        Task<LoginRegisterRefreshResponseModel> RefreshTokenAsync(string jwtToken, string refreshToken);
        Task<LoginRegisterRefreshResponseModel> RegisterUserAsync(RegisterUserModel user);
        Task<LoginRegisterRefreshResponseModel> LogoutAsync(string jwtToken);
        Task<LoginRegisterRefreshResponseModel> RevokeTokenLogoutAsync(string jwtToken);
        Task<LoginRegisterRefreshResponseModel> VerifyEmailConfirmationAsync(string userName, string token);
        Task<LoginRegisterRefreshResponseModel> RequestPasswordResetAsync(string jwtToken);        
        Task<LoginRegisterRefreshResponseModel> VerifyPasswordResetAsync(string jwtToken, string token, string newPassword, string oldPassword);
        Task<LoginRegisterRefreshResponseModel> RequestConfirmationEmailAsync(string userName);
        Task<LoginRegisterRefreshResponseModel> Verify2FactorAuthenticationAsync(string userName, string verificationCode);
        Task<LoginRegisterRefreshResponseModel> Disable2FactorAuthenticationForUserAsync(string userName);        
        Task<LoginRegisterRefreshResponseModel> Request2FACodeAsync(string userName);
        Task<LoginRegisterRefreshResponseModel> Enable2FactorAuthenticationForUserAsync(string userName);
        Task<LoginRegisterRefreshResponseModel> UnlockAccountVerifiedByEmailAsync(string userName, string token);
        Task<LoginRegisterRefreshResponseModel> UnlockAccountVerifiedByAdminAsync(string userName);
        Task<LoginRegisterRefreshResponseModel> LockAccountAsync(string userName);
        Task<LoginRegisterRefreshResponseModel> RequestUnlockAsync(string userName);
        Task<LoginRegisterRefreshResponseModel> UpdateUserDetailsAsync(string jwtToken, RegisterUserModel userUpdateDetails);
        Task<LoginRegisterRefreshResponseModel> ViewUserDetailsAsync(string userName);
    }
}