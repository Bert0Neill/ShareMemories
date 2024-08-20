using AutoMapper;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;

namespace ShareMemories.API.Mappers
{    
    public class RegisterUserProfile : Profile
    {
        public RegisterUserProfile()
        {
            // Define the mapping between RegisterUserDto and RegisterUserModel
            CreateMap<RegisterUserDto, RegisterUserModel>();
        }
    }

}
