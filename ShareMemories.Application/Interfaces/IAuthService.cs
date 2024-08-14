﻿
using Microsoft.AspNetCore.Identity;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IAuthService
    {
        Task<LoginRegisterRefreshResponseDto> LoginAsync(LoginUserDto user);
        Task<LoginRegisterRefreshResponseDto> RefreshTokenAsync(string jwtToken, string refreshToken);
        Task<LoginRegisterRefreshResponseDto> RegisterUserAsync(RegisterUserDto user);
        Task<LoginRegisterRefreshResponseDto> LogoutAsync(string jwtToken);
        Task<LoginRegisterRefreshResponseDto> RevokeRefreshTokenAsync(string jwtToken);
    }
}