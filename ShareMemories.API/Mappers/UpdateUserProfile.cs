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
                .ForMember(dest => dest.IsPersistent, opt => opt.Ignore());  // Ignoring IsPersistent since it's not in UpdateUserDetailsDto
        }
    }

}
