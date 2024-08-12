using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Application.Interfaces
{
    public interface IJwtTokenService
    {
        string GenerateJwtToken(ExtendIdentityUser user, IList<string> roles);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }

}
