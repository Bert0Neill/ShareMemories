namespace ShareMemories.API.Middleware
{
    public class MethodLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<MethodLoggingMiddleware> _logger;

        public MethodLoggingMiddleware(RequestDelegate next, ILogger<MethodLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Capture the HTTP method and path
            var method = context.Request.Method;
            var path = context.Request.Path;

            // Log the method and path
            _logger.LogInformation("Request received: {Method} {Path}", method, path);

            // Call the next middleware in the pipeline
            await _next(context);

            // Log the status code of the response
            var statusCode = context.Response.StatusCode;
            _logger.LogInformation("Response sent: {StatusCode} {Method} {Path}", statusCode, method, path);
        }
    }

}
