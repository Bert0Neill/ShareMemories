using AutoMapper;
using ShareMemories.Domain.Models;
using ShareMemories.Shared.DTOs;

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
