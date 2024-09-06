using ShareMemories.Web.Interfaces;
using System.Text.Json;
using System.Text;
using ShareMemories.Shared.DTOs;

namespace ShareMemories.Web.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly HttpClient _client;
        private readonly JsonSerializerOptions _options;

        public AuthenticationService(HttpClient client)
        {
            _client = client;
            _options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        }

        public async Task<LoginRegisterRefreshResponseDto> RegisterUser(RegisterUserDto userForRegistration)
        {
            var content = JsonSerializer.Serialize(userForRegistration);
            var bodyContent = new StringContent(content, Encoding.UTF8, "application/json");

            var registrationResult = await _client.PostAsync("loginGroup/RegisterAsync", bodyContent);
            var registrationContent = await registrationResult.Content.ReadAsStringAsync();

            if (!registrationResult.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize<LoginRegisterRefreshResponseDto>(registrationContent, _options);
                return result;
            }

            return new LoginRegisterRefreshResponseDto { IsStatus = true };
        }
    }
}
