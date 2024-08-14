using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.InternalServices;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.ExternalServices.Database.Repositories;
using ShareMemories.Infrastructure.ExternalServices.Security;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;
using System;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsSwaggerBuilder
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
