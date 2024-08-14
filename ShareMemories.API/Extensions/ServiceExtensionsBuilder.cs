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

namespace ShareMemories.API.Extensions
{
    public static class ServiceExtensionsBuilder
    {
        public static void AddCustomServices(this IServiceCollection services, IConfiguration configuration, NLog.Logger logger)
        {
            // Add global error handler middleware
            services.AddProblemDetails();
            services.AddExceptionHandler<ExceptionToProblemDetailsHandler>();

            // Add DTO model validation
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

            // Response output caching
            services.AddOutputCache(options =>
            {
                options.AddBasePolicy(builder => builder.Expire(TimeSpan.FromSeconds(5)));
                options.AddPolicy("Expire30", builder => builder.Expire(TimeSpan.FromSeconds(30)));
                options.AddPolicy("Expire60", builder => builder.Expire(TimeSpan.FromSeconds(60)));
            });

            // Register output caching
            services.AddOutputCache();

            // Add Bearer JWT Authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                // options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme; // optional
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateActor = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = configuration.GetSection("Jwt:Issuer").Value,
                    ValidAudience = configuration.GetSection("Jwt:Audience").Value,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetSection("Jwt:Key").Value)),
                };

                // Capture JWT Bearer in the pipeline and assign it to MessageReceivedContext
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        if (context.Request.Cookies.ContainsKey("jwtToken")) // this cookie is assigned in "LoginAsync" endpoint
                        {
                            context.Token = context.Request.Cookies["jwtToken"];
                        }
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        // This event is triggered when a token is successfully validated.
                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = context =>
                    {
                        // This event is triggered when authentication fails.
                        logger.Log(NLog.LogLevel.Error, "An issue extracting JWT Bearer form HttpOnly Cookie");
                        return Task.CompletedTask;
                    }
                };
            });

            // Register Identity services
            services.AddIdentity<ExtendIdentityUser, IdentityRole>(options =>
            {
                // For example: P@ssw0rd
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = true; // For example: !"£$%^
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ShareMemoriesContext>()
            .AddApiEndpoints()
            .AddDefaultTokenProviders();

            // Add Custom Authorization Policies
            services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
                options.AddPolicy("UserPolicy", policy => policy.RequireRole("User"));
                options.AddPolicy("QAPolicy", policy => policy.RequireRole("Qa"));
                options.AddPolicy("UserOrQaPolicy", policy => policy.RequireRole("User", "Qa"));
            });

            services.AddAuthorization();
        }
    }
}
