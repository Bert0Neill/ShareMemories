using ShareMemories.Domain.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Domain.DTOs
{
    public class LoginRegisterRefreshResponseDto : RefreshToken
    {
        public bool IsLoggedIn { get; set; } = false;
        public string Message { get; set; } = string.Empty;
    }
}
