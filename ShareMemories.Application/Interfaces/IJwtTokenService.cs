using ShareMemories.Domain.Entities;
using System.Security.Claims;

namespace ShareMemories.Application.Interfaces
{
    public interface IJwtTokenService
    {
        string GenerateJwtToken(ExtendIdentityUser user, IList<string> roles, int refreshExpire);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }

}
