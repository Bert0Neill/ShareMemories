using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Domain.DTOs
{
    public class RegisterUserDto() : LoginUserDto
    {
        [Required]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        public string LastName { get; set; } = string.Empty;

        [Required]
        public string UserName { get; set; } = string.Empty;

        //[Required, EmailAddress]
        //public string Email { get; set; } = string.Empty;

        //[Required]
        //public string Password { get; set; } = string.Empty;

        [Required, Compare(nameof(Password))]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public DateOnly DateOfBirth { get; set; }         

    }
}
