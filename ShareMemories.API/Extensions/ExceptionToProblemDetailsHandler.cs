using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace ShareMemories.API.Extensions
{
    public class ExceptionToProblemDetailsHandler : Microsoft.AspNetCore.Diagnostics.IExceptionHandler
    {
        private readonly IProblemDetailsService _problemDetailsService;
        private readonly ILogger<ExceptionToProblemDetailsHandler> _logger;

        public ExceptionToProblemDetailsHandler(IProblemDetailsService problemDetailsService, ILogger<ExceptionToProblemDetailsHandler> logger)
        {
            _problemDetailsService = problemDetailsService;
            _logger = logger;
        }

        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            _logger.LogError(exception, "An error occurred while processing the request.");

            // apply the appropriate error status
            httpContext.Response.StatusCode = exception switch
            {
                ArgumentNullException or ArgumentOutOfRangeException => (int)HttpStatusCode.BadRequest,
                UnauthorizedAccessException => (int)HttpStatusCode.Unauthorized,
                KeyNotFoundException => (int)HttpStatusCode.NotFound,
                _ => (int)HttpStatusCode.InternalServerError,
            };

            return await _problemDetailsService.TryWriteAsync(new ProblemDetailsContext
            {
                HttpContext = httpContext,
                ProblemDetails =
                {
                    Title = "ShareMemories.API - Server Error",
                    Detail = exception.Message,
                    Type = exception.GetType().Name //e.g. OutOfRangeException
                },
                Exception = exception // set to null, to stop client seeing sensitive information
            });
        }
    }
}
