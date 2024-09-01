using FluentValidation;
using Mailosaur;
using Mailosaur.Operations;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Serilog;
using ShareMemories.API.Mappers;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.InternalServices;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.ExternalServices.Database.Repositories;
using ShareMemories.Infrastructure.ExternalServices.Email;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsBuilderInitialSetup
    {
        public static void AddServicesInitialSetup(this IServiceCollection services, IConfiguration configuration)
        {
            // add mapper service (AutoMapper)
            services.AddAutoMapper(typeof(Program));

            // Register AutoMapper and the mapping profiles
            services.AddAutoMapper(typeof(LoginProfile));
            services.AddAutoMapper(typeof(RegisterUserProfile));
            services.AddAutoMapper(typeof(LoginRegisterRefreshResponseProfile));
            services.AddAutoMapper(typeof(UpdateUserProfile));

            // Register the IMemoryCache service for revoking invalidated JWT's
            services.AddMemoryCache();

            // Add DTO model validation (from client)
            services.AddValidatorsFromAssemblyContaining(typeof(PictureValidator));
            services.AddValidatorsFromAssemblyContaining(typeof(LoginUserValidator));

            // Register DbContext
            services.AddDbContext<ShareMemoriesContext>(db =>
                db.UseSqlServer(configuration.GetConnectionString("DefaultConnection")),
                ServiceLifetime.Singleton);

            // Register DI for email provider (MailosaurClient) - NB: you can replace with your company SMTP or another email provider
            services.AddSingleton<MailosaurClient>(sp =>
            {
                return new MailosaurClient(configuration["Mailosaur:ApiKey"]); // Read from configuration
            });

            // Dependency Injection
            services.AddScoped<IPictureService, PictureService>();          // Application
            services.AddScoped<IVideoService, VideoService>();              // Application
            services.AddScoped<IAuthService, AuthService>();                // Application
            services.AddScoped<IPictureRepository, PictureRepository>();    // Infrastructure
            services.AddScoped<IVideoRepository, VideoRepository>();        // Infrastructure
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
