using Microsoft.AspNetCore.Identity;


namespace ShareMemories.Domain.Entities
{
    public class ExtendIdentityUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateOnly DateOfBirth { get; set; }
        public bool? IsArchived { get; set; } = false;
        public DateTime? LastUpdated { get; set; }
        public DateTime? CreatedDate { get; set; } = DateTime.Now;
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiry { get; set; }
    }

}
