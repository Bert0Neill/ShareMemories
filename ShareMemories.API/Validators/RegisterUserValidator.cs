using FluentValidation;
using ShareMemories.Domain.DTOs;
using System.Text.RegularExpressions;

namespace ShareMemories.API.Validators
{
    public class RegisterUserValidator : AbstractValidator<RegisterUserDto>
    {
        public RegisterUserValidator()
        {
            RuleFor(p => p.Email)
                .NotEmpty()
                .WithMessage("Email must not be blank");

            RuleFor(p => p.UserName)
              .MinimumLength(1)
              .MaximumLength(100)
              .NotEmpty()
              .WithMessage("Username must be >= 1 and <= 100 characters");

            RuleFor(p => p.FirstName)
               .MinimumLength(1)
               .MaximumLength(100)
               .NotEmpty()
               .WithMessage("First name must be >= 1 and <= 100 characters");

            RuleFor(p => p.LastName)
               .MinimumLength(1)
               .MaximumLength(100)
               .NotEmpty()
               .WithMessage("Second name must be >= 1 and <= 100 characters");

            RuleFor(p => p.Password)
               .NotEmpty()
               .WithMessage("Password must not be blank")

               .Must(password => Regex.IsMatch(password!, @"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()-=_+|\\[\]{};:'"",.<>?]).{8,}$")) // it MUST pass this
               .WithMessage("Must be a valid 'Password'");

            RuleFor(x => x.ConfirmPassword)
               .NotEmpty()
               .WithMessage("Please confirm your password")

               .Equal(x => x.Password)
               .WithMessage("Passwords do not match");
        }
    }
}
