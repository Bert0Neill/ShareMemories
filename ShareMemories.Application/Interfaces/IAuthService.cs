
using Microsoft.AspNetCore.Identity;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginUser user);
        Task<LoginResponse> RefreshTokenAsync(RefreshTokenModel model);
        Task<IEnumerable<IdentityError>> RegisterUserAsync(LoginUser user);

    }
}