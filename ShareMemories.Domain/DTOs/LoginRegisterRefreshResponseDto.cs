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
        public bool IsStatus { get; set; } = false;
        public bool IsRefreshRevoked { get; set; } = true;
        public string Message { get; set; } = string.Empty;
    }
}
