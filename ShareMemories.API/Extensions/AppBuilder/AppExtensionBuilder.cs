﻿using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ShareMemories.API.Endpoints.Auth;
using ShareMemories.API.Endpoints.Picture;
using ShareMemories.API.Endpoints.Video;
using ShareMemories.API.Middleware;

namespace ShareMemories.API.Extensions.AppBuilder
{
    public static class AppExtensionBuilder
    {
        public static void ConfigureMiddleware(this IApplicationBuilder app, IHostEnvironment env)
        {
            // Add the middleware
            app.UseMiddleware<ExceptionHandlingMiddleware>();

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

            app.UseCors("AllowSpecificOrigins"); // apply the CORS policy
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
