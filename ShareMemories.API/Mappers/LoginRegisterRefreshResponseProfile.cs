using AutoMapper;
using ShareMemories.Domain.DTOs;
using ShareMemories.Domain.Models;

namespace ShareMemories.API.Mappers
{    
    public class LoginRegisterRefreshResponseProfile : Profile
    {
        public LoginRegisterRefreshResponseProfile()
        {
            // Define the mapping between LoginRegisterRefreshResponseModel and LoginRegisterRefreshResponseDto
            CreateMap<LoginRegisterRefreshResponseModel, LoginRegisterRefreshResponseDto>();
        }
    }

}
