using System.Text.Json.Serialization;

namespace ShareMemories.Shared.DTOs
{
    public class UpdateUserDetailsDto()
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public DateOnly DateOfBirth { get; set; }
        public string PhoneNumber { get; set; } = string.Empty;
    }
}
