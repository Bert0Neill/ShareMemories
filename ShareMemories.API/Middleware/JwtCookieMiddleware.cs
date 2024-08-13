namespace ShareMemories.API.Middleware
{
    public class JwtCookieMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtCookieMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Cookies.TryGetValue("jwtToken", out var token))
            {
                context.Request.Headers.Add("Authorization", $"Bearer {token}");
                Console.WriteLine($"Token added to Authorization header: {token}"); // Debug output
            }
            else
            {
                Console.WriteLine("No AuthToken found in cookies."); // Debug output
            }

            await _next(context);
        }
    }

}
