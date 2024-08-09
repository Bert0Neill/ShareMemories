
using Microsoft.AspNetCore.Identity;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IAuthService
    {
        Task<LoginResponseDto> LoginAsync(LoginUserDto user);
        Task<LoginResponseDto> RefreshTokenAsync(RefreshTokenModel model);
        Task<IdentityResult> RegisterUserAsync(RegisterUserDto user);

    }
}