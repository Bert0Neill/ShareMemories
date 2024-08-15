using System.Net;

namespace ShareMemories.API.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;

        public ExceptionHandlingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (ArgumentNullException ex)
            {
                await HandleExceptionAsync(context, ex);
            }
            // Catch other exceptions as needed
        }

        private Task HandleExceptionAsync(HttpContext context, Exception ex)
        {
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest; // Set the status code based on the exception

            var response = new
            {
                Error = ex.GetType().Name,
                Message = ex.Message
            };

            return context.Response.WriteAsJsonAsync(response);
        }
    }

}
