using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SendGrid.Extensions.DependencyInjection;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using System.Text;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsBuilderJwtIdentity
    {
        public static void AddServicesJwtIdentity(this IServiceCollection services, IConfiguration configuration, NLog.Logger logger)
        {
            // Add Bearer JWT Authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
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
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetSection("Jwt:Key").Value!)),
                };

                // Capture JWT Bearer in the pipeline and assign it to MessageReceivedContext
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        if (context.Request.Cookies.ContainsKey("jwtToken")) // this cookie is assigned after "LoginAsync" endpoint called
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

                // Confirm Email options
                options.SignIn.RequireConfirmedEmail = true;
                options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider; // this will create a shorter code for the user to copy & paste

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings.
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = false;

            })
            .AddEntityFrameworkStores<ShareMemoriesContext>()
            .AddApiEndpoints()
            .AddDefaultTokenProviders();

            // load email service settings for email confirmation
            services.AddSendGrid(options => options.ApiKey = configuration.GetSection("SendGrid:SendGridKey").Value);

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
