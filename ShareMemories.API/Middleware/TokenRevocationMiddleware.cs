using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using System.IdentityModel.Tokens.Jwt;

namespace ShareMemories.API.Middleware
{
    public class TokenRevocationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IMemoryCache _memoryCache;
        private readonly ILogger<TokenRevocationMiddleware> _logger;

        public TokenRevocationMiddleware(RequestDelegate next, IMemoryCache memoryCache, ILogger<TokenRevocationMiddleware> logger)
        {
            _next = next;
            _memoryCache = memoryCache;
            _logger = logger;            
        }

        public async Task InvokeAsync(HttpContext context)
        {
            _logger.LogInformation("Processing request: {Path}", context.Request.Path);

            var token = context.Request.Cookies["jwtToken"];

            if (token != null)
            {
                // verify that JWT hasn't been revoked
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadJwtToken(token);
                var jti = jwtToken?.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value;

                if (jti != null && _memoryCache.TryGetValue(jti, out bool isRevoked) && isRevoked)
                {
                    _logger.LogInformation($"JWT has already been revoked - {jwtToken}");

                    await JwtTokenMissingInvalidRequest(context, "API request has been cancelled - Token has been revoked.");
                    return;
                }
            }            

            await _next(context);
        }

        private static async Task JwtTokenMissingInvalidRequest(HttpContext context, string message)
        {
            // stop use from using these tokens again - clear related cookies for security reasons
            context.Response.Cookies.Delete("jwtToken");
            context.Response.Cookies.Delete("jwtRefreshToken");

            // notify user that their (token) request is invalid
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync(message);            
        }
    }

}
