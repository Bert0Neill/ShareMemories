using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Domain.Models
{
    public class UpdateUserDetailsModel() : RegisterUserModel
    {
        // Hides properties from inherited classes by using "New"
        public new string? ConfirmPassword { get; set; }
        public new string? Password { get; set; }
        public new string? UserName { get; set; }
        public new bool? IsPersistent { get; set; }

        // Remove the [Required] attribute by redefining the properties without the attribute
        public new string FirstName { get; set; } = string.Empty;
        public new string LastName { get; set; } = string.Empty;
        public new string Email { get; set; } = string.Empty;
        public new DateOnly DateOfBirth { get; set; }        
        public new string PhoneNumber { get; set; } = string.Empty;
    }
}
