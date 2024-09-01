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
            CreateMap<LoginUserDto, LoginUserModel>();
        }
    }

}
