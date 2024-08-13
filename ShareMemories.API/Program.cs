using FluentValidation;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Endpoints.Auth;
using ShareMemories.API.Endpoints.Picture;
using ShareMemories.API.Endpoints.Video;
using ShareMemories.API.Extensions;
using ShareMemories.API.Middleware;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.InternalServices;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.ExternalServices.Database.Repositories;
using ShareMemories.Infrastructure.ExternalServices.Security;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;
using System.Security.Claims;
using System.Security.Cryptography.Xml;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

try
{
    /*************************************************************************
    * Associate a Global Error handler middleware for your end-points        *
    **************************************************************************/
    builder.Services.AddProblemDetails(); // add ProblemDetails handler - consistent error response
    builder.Services.AddExceptionHandler<ExceptionToProblemDetailsHandler>(); // notify services of your custom error handling, by using "app.UseExceptionHandler()" you are telling the system to use it

    /**********************************************************************************
     * Add DTO model validation - Minimal API doesn't do Model.Validation like MVC
     **********************************************************************************/
    builder.Services.AddValidatorsFromAssemblyContaining(typeof(PictureValidator));
    builder.Services.AddValidatorsFromAssemblyContaining(typeof(LoginUserValidator));

    /*************************************************************************
    *           Register DbContext and provide ConnectionString              *
    **************************************************************************/
    builder.Services.AddDbContext<ShareMemoriesContext>(db => db.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")), ServiceLifetime.Singleton);

    /********************************************************************************
    * Register EXTENDED ExtendIdentityUser Endpoints (Register\login\Refresh etc.)  *
    *********************************************************************************/
    //builder.Services
    //    .AddIdentityApiEndpoints<ExtendIdentityUser>()
    //    .AddEntityFrameworkStores<ShareMemoriesContext>()
    //    .AddApiEndpoints();

    /*************************************************************************
    *                       Dependency Injection                             *
    **************************************************************************/
    builder.Services.AddScoped<IPictureService, PictureService>();          // Application
    builder.Services.AddScoped<IAuthService, AuthService>();                // Application
    builder.Services.AddScoped<IPictureRepository, PictureRepository>();    // Infrastructure
    builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();        // Infrastructure

    /*************************************************************************
     *   Response output caching (duration) policies - default is 5 seconds  *
     **************************************************************************/
    builder.Services.AddOutputCache(options =>
    {
        options.AddBasePolicy(builder => builder.Expire(TimeSpan.FromSeconds(5)));
        options.AddPolicy("Expire30", builder => builder.Expire(TimeSpan.FromSeconds(30)));
        options.AddPolicy("Expire60", builder => builder.Expire(TimeSpan.FromSeconds(60)));
    });

    /*************************************************************************
    *                           Register Response Caching                   *
    **************************************************************************/
    builder.Services.AddOutputCache();

    /*************************************************************************
    *                       Add Bearer JWT Authentication                    *
    **************************************************************************/
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;



    })
      .AddCookie(x => { x.Cookie.Name = "jwtToken"; })

      .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateActor = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            RequireExpirationTime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration.GetSection("Jwt:Issuer").Value,
            ValidAudience = builder.Configuration.GetSection("Jwt:Audience").Value,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetSection("Jwt:Key").Value)),

            // **This line maps the custom role claim**
            //RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",



            //ValidateLifetime = true,
            //ClockSkew = TimeSpan.Zero,

        };

        // Middleware that will extract out custom cookie called "jwtToken" and assign it to the request Token property (if found)
        //options.Events = new JwtBearerEvents
        //{
        //    OnMessageReceived = context =>
        //    {
        //        if (context.Request.Cookies.ContainsKey("jwtToken")) // this cookie is assigned in "LoginAsync" endpoint
        //        {
        //            context.Token = context.Request.Cookies["jwtToken"];
        //        }
        //        return Task.CompletedTask;
        //    }
        //};

        options.Events = new JwtBearerEvents
        {

            OnChallenge = context =>
            {
                // Prevent default redirect behavior
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync("{\"error\":\"Unauthorized\"}");
            },

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
                logger.Error(context.Exception);
                // This event is triggered when authentication fails.
                return Task.CompletedTask;
            }
        };
    });

    //// add Cookie provider for HttpOnly data
    //.AddCookie(options =>
    // {
    //     options.Events.OnRedirectToLogin = c =>
    //     {
    //         c.Response.StatusCode = StatusCodes.Status401Unauthorized;
    //         return Task.FromResult<object>(null);
    //     };
    // });
    var multiSchemePolicy = new AuthorizationPolicyBuilder(
        CookieAuthenticationDefaults.AuthenticationScheme,
        JwtBearerDefaults.AuthenticationScheme)
      .RequireAuthenticatedUser()
      .Build();

    builder.Services.AddAuthorization(o => o.DefaultPolicy = multiSchemePolicy);


    /********************************************************************************
    *                           Add Password strength                               *
    *                                      &                                        *
    * Register EXTENDED ExtendIdentityUser Endpoints (Register\login\Refresh etc.)  *
    *********************************************************************************/
    builder.Services.AddIdentity<ExtendIdentityUser, IdentityRole>(options =>
    {
        //// for e.g. P@ssw0rd
        //options.Password.RequiredLength = 8;
        //options.Password.RequireNonAlphanumeric = true; // for e.g. !"£$%^
        //options.Password.RequireDigit = true;
        //options.Password.RequireLowercase = true;
        //options.Password.RequireUppercase = true;
        //options.User.RequireUniqueEmail = true;

    })
        .AddEntityFrameworkStores<ShareMemoriesContext>()
        .AddSignInManager()
        .AddRoles<IdentityRole>();
    //.AddApiEndpoints()
    //.AddDefaultTokenProviders();

    /*************************************************************************
    *               Add Custom Authorization Policies                        *
    **************************************************************************/
    //builder.Services.AddAuthorization(options =>
    //{
    //    // Policy for Admin role
    //    options.AddPolicy("AdminPolicy", policy =>
    //        policy.RequireRole("Admin"));

    //    // Policy for User role
    //    options.AddPolicy("UserPolicy", policy =>
    //        policy.RequireRole("User"));

    //    // Policy for QA role
    //    options.AddPolicy("QAPolicy", policy =>
    //        policy.RequireRole("Qa"));

    //    // Policy for User or QA role
    //    options.AddPolicy("UserOrQaPolicy", policy =>
    //        policy.RequireRole("User", "Qa"));
    //});

    builder.Services.AddAuthorizationBuilder()
        .AddPolicy("UserOnlyPolicy", o =>
        {
            o.RequireAuthenticatedUser();
            o.RequireRole("User");
        })
         .AddPolicy("AdminOnlyPolicy", o =>
         {
             o.RequireAuthenticatedUser();
             o.RequireRole("Admin");
         });



    builder.Services.AddEndpointsApiExplorer();
    // builder.Services.AddSwaggerGen();

    // allow Swagger to use JWT Bearer Tokens when calling secure API endpoints
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo { Version= "v1" });

        c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
        {
            Name = "Authorization",
            //Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
            Type = SecuritySchemeType.ApiKey,
            BearerFormat = "JWT",
            Scheme = "Bearer",
            In = ParameterLocation.Header
        });

        c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
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

    /*************************************************************************
    *               Add Authorization & Authentication                       *
    **************************************************************************/
    builder.Services.AddAuthorization();
    //builder.Services.AddAuthentication();
    

    var app = builder.Build();


    ///*************************************************
    ///* Apply security middleware 
    //*************************************************/
    //app.UseMiddleware<JwtCookieMiddleware>(); // ???? needed ????
    app.UseAuthentication(); // Authenticate the token
    app.UseAuthorization();  // Authorize based on roles/policies

    /*************************************************************************
    *                       Register Minimal APIEndpoints                    *
    **************************************************************************/
    app.MapPictureEndpoints();
    app.MapVideoEndpoints();
    app.MapAuthEndpoints();

    /*************************************************************************
    *                         Use Output Caching                             *
    **************************************************************************/
    app.UseOutputCache();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();

    // Test authentication API when logged in
    app.MapGet("/testAuthenticationWhenLoggedIn", (ClaimsPrincipal user) => $"Hello {user.Identity!.Name}")
        .RequireAuthorization();

    
    app.MapGet("/admin-data", [Authorize(Policy = "AdminPolicy")] () =>
    {
        return Results.Ok("This data is accessible by Admins.");
    });

    //app.MapGet("/userQaData", () =>
    app.MapGet("/userPolicy", [Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme, Policy = "UserOnlyPolicy")] () =>
    //app.MapGet("/userQaData", [Authorize(Roles = "User")] () =>
    {
        return Results.Ok("This data is accessible by User Or Qa.");
    });
    //}).RequireAuthorization("UserOnlyPolicy");
    //}).RequireAuthorization();

    app.MapGet("/Secure", (ClaimsPrincipal user) =>
    {
        var data = user.Identity!.Name;
        return Results.Ok("This data is accessible by Authorize User.");
    }).RequireAuthorization();
    

    app.MapGet("/NotSecure", () =>
    {
        return Results.Ok("This data is accessible by everyone.");
    });

    app.MapGet("/SecureInspectClaims", [Authorize] (HttpContext httpContext) =>
    {
        var claims = httpContext.User.Claims.Select(c => new { c.Type, c.Value }).ToList();
        return Results.Ok(claims);
    });

    app.Run();
}
catch (Exception exception)
{
    // NLog: catch setup errors
    logger.Error(exception, "Stopped program because of exception");
    throw;
}
finally
{
    // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
    NLog.LogManager.Shutdown();
}
