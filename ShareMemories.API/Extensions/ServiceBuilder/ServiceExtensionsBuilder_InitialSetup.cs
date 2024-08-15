using FluentValidation;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.InternalServices;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.ExternalServices.Database.Repositories;
using ShareMemories.Infrastructure.ExternalServices.Email;
using ShareMemories.Infrastructure.ExternalServices.Security;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsBuilderInitialSetup
    {
        public static void AddServicesInitialSetup(this IServiceCollection services, IConfiguration configuration, NLog.Logger logger)
        {
            // Add global error handler middleware
            services.AddProblemDetails();
            services.AddExceptionHandler<ExceptionToProblemDetailsHandler>();

            // Add DTO model validation (from client)
            services.AddValidatorsFromAssemblyContaining(typeof(PictureValidator));
            services.AddValidatorsFromAssemblyContaining(typeof(LoginUserValidator));

            // Register DbContext
            services.AddDbContext<ShareMemoriesContext>(db =>
                db.UseSqlServer(configuration.GetConnectionString("DefaultConnection")),
                ServiceLifetime.Singleton);

            // Dependency Injection
            services.AddScoped<IPictureService, PictureService>();          // Application
            services.AddScoped<IAuthService, AuthService>();                // Application
            services.AddScoped<IPictureRepository, PictureRepository>();    // Infrastructure
            services.AddScoped<IJwtTokenService, JwtTokenService>();        // Infrastructure
            services.AddTransient<IEmailSender, EmailService>();            // Infrastructure

            // Generate response output caching policies
            services.AddOutputCache(options =>
            {
                options.AddBasePolicy(builder => builder.Expire(TimeSpan.FromSeconds(5)));
                options.AddPolicy("Expire30", builder => builder.Expire(TimeSpan.FromSeconds(30)));
                options.AddPolicy("Expire60", builder => builder.Expire(TimeSpan.FromSeconds(60)));
            });

            // Register output caching
            services.AddOutputCache();
        }
    }
}
