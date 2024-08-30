using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SendGrid.Extensions.DependencyInjection;
using Serilog;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using System.Text;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsBuilderJwtIdentity
    {
        public static void AddServicesJwtIdentity(this IServiceCollection services, IConfiguration configuration)
        {
            int tokenLifeSpanMinutes = int.Parse(configuration.GetSection("SystemDefaults:ProviderTokenLifeSpan").Value);
            int lockoutLifeSpanMinutes = int.Parse(configuration.GetSection("SystemDefaults:LockoutLifeSpan").Value);
            int lockoutAttempts = int.Parse(configuration.GetSection("SystemDefaults:LockoutAttempts").Value);
            
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
                        else
                        {
                            Log.Logger.Information("JWT token missing");
                            context.Fail("JWT token missing.");
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
                        Log.Logger.Error("An issue extracting JWT Bearer form HttpOnly Cookie");
                        return Task.CompletedTask;
                    }
                };
            });

            // Register Identity services
            services.AddIdentity<ExtendIdentityUser, IdentityRole>(options =>
            {
                // Enforce password rules - For example: P@ssw0rd
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = true; // For example: !"£$%^
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;

                // Confirm Email options
                options.SignIn.RequireConfirmedEmail = true; // set to false if user is not to confirm their email address when registering

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(lockoutLifeSpanMinutes);
                options.Lockout.MaxFailedAccessAttempts = lockoutAttempts;
                options.Lockout.AllowedForNewUsers = true;

                // User settings.
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = true;

                // confirm Token settings
                options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultEmailProvider;      // provider for  2FA                
                options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;  // provider for email confirmation
                options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider;      // provider for password reset
            })
            .AddEntityFrameworkStores<ShareMemoriesContext>()
            .AddApiEndpoints()
            .AddDefaultTokenProviders();

            // configure the timeout for a token (Confirmation email , 2FA etc.), before it expires. Defaults to 1 day. Used as part of Registration process.
            services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromMinutes(tokenLifeSpanMinutes); // Set the email token lifespan (2FA or Confirm Email in registration)
            });

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
