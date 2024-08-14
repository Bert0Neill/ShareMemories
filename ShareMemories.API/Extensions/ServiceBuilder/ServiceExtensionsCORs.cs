using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.InternalServices;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.ExternalServices.Database.Repositories;
using ShareMemories.Infrastructure.ExternalServices.Security;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;
using System.Text;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsCORs
    {
        public static void AddCORsServices(this IServiceCollection services, IConfiguration configuration, NLog.Logger logger)
        {
            // Configure CORS
            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigins",
                    policyBuilder =>
                    {
                        policyBuilder.WithOrigins("https://example.com", "https://anotherdomain.com") // Allowed origins
                                    .AllowAnyMethod() // Allowed HTTP methods
                                    .AllowAnyHeader() // Allowed headers
                                    .AllowCredentials(); // Allow credentials (cookies)
                    });

                // Add other policies as needed - development\testing
                // options.AddPolicy("AllowAllOrigins", policyBuilder => policyBuilder.AllowAnyOrigin());
            });

        }
    }
}
