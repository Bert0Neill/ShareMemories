using FluentValidation;
using ShareMemories.Domain.DTOs;
using System;
using System.Text.RegularExpressions;

namespace ShareMemories.API.Validators
{
    public class LoginUserValidator : AbstractValidator<LoginUser>
    {
        public LoginUserValidator()
        {            
            RuleFor(p => p.UserName).MinimumLength(8).MaximumLength(100).NotEmpty().WithMessage("Username must be >= 8 and <= 100 characters");

            RuleFor(p => p.Password)
               .NotEmpty()
               .WithMessage("'Password' must not be empty")

               .Must(phone => Regex.IsMatch(phone!, @"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()-=_+|\\[\]{};:'"",.<>?]).{8,}$")) // it MUST pass this
               .WithMessage("Must be a valid 'Password'");
        }
    }
}
