using Microsoft.OpenApi.Models;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsBuilderSwagger
    {
        public static void AddCustomServicesSwagger(this IServiceCollection services, IConfiguration configuration, NLog.Logger logger)
        {
            services.AddEndpointsApiExplorer();

            // allow Swagger to use JWT Bearer Tokens when calling secure API endpoints
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Version = "v1" });

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    //Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
                    Type = SecuritySchemeType.ApiKey,
                    BearerFormat = "JWT",
                    Scheme = "Bearer",
                    In = ParameterLocation.Header
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                Array.Empty<string>() // pass in empty collection
            }
        });

            });
        }
    }
}
