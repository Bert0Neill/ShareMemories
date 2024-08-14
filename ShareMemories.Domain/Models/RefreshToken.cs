using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Domain.Models
{
    public class RefreshToken
    {
        public string JwtToken { get; set; }
        public string JwtRefreshToken { get; set; }
    }
}
