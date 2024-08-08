using Microsoft.AspNet.Identity.EntityFramework;

namespace ShareMemories.Domain.Models
{
    public class ExtendedIdentityUser : IdentityUser
    {
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }
    }
}
