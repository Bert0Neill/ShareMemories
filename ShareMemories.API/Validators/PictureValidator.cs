using FluentValidation;
using ShareMemories.Domain.Entities;

namespace ShareMemories.API.Validators
{
    public class PictureValidator : AbstractValidator<Picture>
    {
        public PictureValidator()
        {
            RuleFor(p => p.UserId).GreaterThan(0).NotEmpty().WithMessage("Not able to associate picture with user");            
            RuleFor(p => p.FriendlyName).MaximumLength(100).NotEmpty().WithMessage("'Friendly Name' missing (must be < 100 characters)");
            RuleFor(p => p.PictureBytes).NotEmpty().WithMessage("No picture selected to upload");            
        }
    }
}
