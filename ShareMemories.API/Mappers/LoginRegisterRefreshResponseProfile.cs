using AutoMapper;
using ShareMemories.Domain.Models;
using ShareMemories.Shared.DTOs;

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
