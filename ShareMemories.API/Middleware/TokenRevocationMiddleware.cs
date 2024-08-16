using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using System.IdentityModel.Tokens.Jwt;

namespace ShareMemories.API.Middleware
{
    public class TokenRevocationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IMemoryCache _memoryCache;

        public TokenRevocationMiddleware(RequestDelegate next, IMemoryCache memoryCache)
        {
            _next = next;
            _memoryCache = memoryCache;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var token = context.Request.Cookies["jwtToken"];

            if (token != null)
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadJwtToken(token);
                var jti = jwtToken?.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value;

                if (jti != null && _memoryCache.TryGetValue(jti, out bool isRevoked) && isRevoked)
                {
                    // stop use from using these tokens again - clear related cookies for security reasons
                    context.Response.Cookies.Delete("jwtToken");
                    context.Response.Cookies.Delete("jwtRefreshToken");

                    // notify user that their (token) request is invalid
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("API request has been cancelled - Token has been revoked.");
                    return;
                }
            }

            await _next(context);
        }
    }

}
