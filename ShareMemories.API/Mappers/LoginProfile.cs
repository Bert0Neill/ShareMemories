using AutoMapper;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;

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
