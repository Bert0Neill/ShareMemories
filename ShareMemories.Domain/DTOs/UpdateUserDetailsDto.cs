using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using ShareMemories.Domain.Models;

namespace ShareMemories.Domain.DTOs
{
    public class UpdateUserDetailsDto() : RegisterUserModel
    {
    
        // hide certain inherited properties that can't be changed or supplied form client
        [JsonIgnore] public new string? ConfirmPassword { get; set; }
        [JsonIgnore] public new string? Password { get; set; }
        [JsonIgnore] public new string? UserName { get; set; }
        [JsonIgnore] public new bool IsPersistent { get; set; }

        // Remove the [Required] attribute by redefining the properties without the attribute - not everything has to be entered
        public new string FirstName { get; set; } = string.Empty;
        public new string LastName { get; set; } = string.Empty;
        public new string Email { get; set; } = string.Empty;
        public new DateOnly DateOfBirth { get; set; }
        public new string PhoneNumber { get; set; } = string.Empty;
    }
}
