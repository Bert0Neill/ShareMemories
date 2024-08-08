using FluentValidation;
using ShareMemories.Domain.Models;
using System;

namespace ShareMemories.API.Validators
{
    public class BookValidator : AbstractValidator<Book>
    {
        public BookValidator()
        {
            RuleFor(p => p.Id).GreaterThan(0);
            RuleFor(p => p.Author).MaximumLength(255).NotEmpty().WithMessage("Must be a valid 'Author'");
            RuleFor(p => p.Title).MaximumLength(255).NotEmpty().WithMessage("Must be a valid 'Title'");            
        }
    }

    public class BookIdValidator : AbstractValidator<Book>
    {
        public BookIdValidator()
        {
            RuleFor(p => p.Id).GreaterThan(0).WithMessage("Id must not be negative");
            RuleFor(p => p.Id).NotEmpty().WithMessage("Id must not be empty");            
        }
    }

}
