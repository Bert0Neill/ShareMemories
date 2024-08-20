namespace ShareMemories.Domain.Models
{
    public class LoginRegisterRefreshResponseModel : RefreshTokenModel
    {
        public bool IsStatus { get; set; } = false;
        public string Message { get; set; } = string.Empty;
    }
}
