using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ShareMemories.API.Endpoints.Auth;
using ShareMemories.API.Endpoints.Picture;
using ShareMemories.API.Endpoints.Video;

namespace ShareMemories.API.Extensions.AppBuilder
{
    public static class AppExtensionBuilder
    {
        public static void ConfigureMiddleware(this IApplicationBuilder app, IHostEnvironment env)
        {
            // Apply security middleware
            app.UseAuthentication(); // Authenticate the token
            app.UseAuthorization();  // Authorize based on roles/policies

            // Use Output Caching
            app.UseOutputCache();

            // Configure the HTTP request pipeline.
            if (env.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
        }

        public static void ConfigureEndpoints(this WebApplication app)
        {
            // Register Minimal API Endpoints
            app.MapPictureEndpoints();
            app.MapVideoEndpoints();
            app.MapAuthEndpoints();
        }
    }
}
