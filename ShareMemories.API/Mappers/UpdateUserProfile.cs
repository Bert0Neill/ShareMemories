using AutoMapper;
using ShareMemories.Domain.Models;
using ShareMemories.Shared.DTOs;

namespace ShareMemories.API.Mappers
{
    public class UpdateUserProfile : Profile
    {
        public UpdateUserProfile()
        {
            // Define the mapping between UpdateUserDetailsDto and RegisterUserModel
            CreateMap<UpdateUserDetailsDto, RegisterUserModel>()
              .ForMember(dest => dest.UserName, opt => opt.Ignore())  // Ignoring UserName since it's not in UpdateUserDetailsDto
              .ForMember(dest => dest.Password, opt => opt.Ignore())  // Ignoring Password since it's not in UpdateUserDetailsDto
              .ForMember(dest => dest.ConfirmPassword, opt => opt.Ignore())  // Ignoring ConfirmPassword since it's not in UpdateUserDetailsDto
              .ForMember(dest => dest.IsPersistent, opt => opt.Ignore())  // Ignoring IsPersistent since it's not in UpdateUserDetailsDto

              // trim values
              .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email.Trim()))
              .ForMember(dest => dest.FirstName, opt => opt.MapFrom(src => src.FirstName.Trim()))
              .ForMember(dest => dest.LastName, opt => opt.MapFrom(src => src.LastName.Trim()))
              .ForMember(dest => dest.PhoneNumber, opt => opt.MapFrom(src => src.PhoneNumber.Trim()));
        }
    }

}
