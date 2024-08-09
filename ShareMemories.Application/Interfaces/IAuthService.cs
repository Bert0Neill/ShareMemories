
using Microsoft.AspNetCore.Identity;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IAuthService
    {
        Task<LoginRegisterResponseDto> LoginAsync(LoginUserDto user);
        Task<LoginRegisterResponseDto> RefreshTokenAsync(RefreshTokenModel model);
        Task<LoginRegisterResponseDto> RegisterUserAsync(RegisterUserDto user);

    }
}