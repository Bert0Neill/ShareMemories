﻿namespace ShareMemories.Shared.DTOs
{
    public class LoginRegisterRefreshResponseDto : RefreshTokenDto
    {
        public bool IsStatus { get; set; } = false;
        public string Message { get; set; } = string.Empty;
    }
}
