using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.SharedDto.DTOs
{
    public class LoginUserDto()
    {
        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;
        public bool IsPersistent  { get; set; } = false;
    }
}
