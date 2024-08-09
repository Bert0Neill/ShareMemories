using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Domain.DTOs
{
    public class LoginResponseDto
    {
        public bool IsLoggedIn { get; set; } = false;
        public string JwtToken { get; set; }
        public string RefreshToken { get; set; }
        public string Message { get; set; }
    }
}
