using AutoMapper;
using ShareMemories.Domain.Models;
using ShareMemories.Shared.DTOs;

namespace ShareMemories.API.Mappers
{
    public class LoginProfile : Profile
    {
        public LoginProfile()
        {
            // Define the mapping between LoginUserDto and LoginUserModel
            CreateMap<LoginUserDto, LoginUserModel>()
              // trim values
              .ForMember(dest => dest.Password, opt => opt.MapFrom(src => src.Password.Trim()))
              .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.UserName.Trim()));
        }
    }

}
