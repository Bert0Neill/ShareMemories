using FluentValidation;
using ShareMemories.Domain.DTOs;
using System;
using System.Text.RegularExpressions;

namespace ShareMemories.API.Validators
{
    public class LoginUserValidator : AbstractValidator<LoginUserDto>
    {
        public LoginUserValidator()
        {
            RuleFor(p => p.UserName)
                .NotEmpty()
                .WithMessage("Username must not be blank");

            RuleFor(p => p.Password)
               .NotEmpty()
               .WithMessage("'Password' must not be empty")

               .Must(password => Regex.IsMatch(password!, @"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()-=_+|\\[\]{};:'"",.<>?]).{8,}$")) // it MUST pass this
               .WithMessage("Must be a valid 'Password'");
        }
    }
}
