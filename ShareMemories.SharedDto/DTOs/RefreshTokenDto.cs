using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Shared.DTOs
{
    public class RefreshTokenDto()
    {
        public string JwtToken { get; set; } = string.Empty;    
        public string JwtRefreshToken { get; set; } = string.Empty;

        public DateTime JwtRefreshTokenExpire { get; set; } = DateTime.Now;
        public DateTime JwtTokenExpire { get; set; } = DateTime.Now;
    }
}
