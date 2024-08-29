using FluentValidation;
using ShareMemories.Domain.Entities;

namespace ShareMemories.API.Validators
{
    public class VideoValidator : AbstractValidator<Video>
    {
        public VideoValidator()
        {
            RuleFor(p => p.UserId).GreaterThan(0).NotEmpty().WithMessage("Not able to associate video with user");            
            RuleFor(p => p.FriendlyName).MaximumLength(100).NotEmpty().WithMessage("'Friendly Name' missing (must be < 100 characters)");
            RuleFor(p => p.VideoBytes).NotEmpty().WithMessage("No video selected to upload");            
        }
    }
}
