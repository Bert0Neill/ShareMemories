using ShareMemories.Shared.DTOs;

namespace ShareMemories.Web.Interfaces
{
    public interface IAuthenticationService
    {
        Task<LoginRegisterRefreshResponseDto> RegisterUser(RegisterUserDto userForRegistration);
    }
}
