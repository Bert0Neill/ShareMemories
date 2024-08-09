using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShareMemories.API.Endpoints.Auth;
using ShareMemories.API.Endpoints.Picture;
using ShareMemories.API.Endpoints.Video;
using ShareMemories.API.Extensions;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.InternalServices;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.ExternalServices.Database.Repositories;
using ShareMemories.Infrastructure.Interfaces;
using System.Security.Claims;
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
    
    /*************************************************************************
    *                       Dependency Injection                             *
    **************************************************************************/
    //builder.Services.AddTransient<IDistributedService, SqlServerDistributedService>(); // DI service class
    builder.Services.AddScoped<IPictureService, PictureService>();
    builder.Services.AddScoped<IPictureRepository, PictureRepository>();
    //builder.Services.AddScoped<IAuthService, AuthService>();

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
    *       Register Identity Endpoints (Register\login\Refresh etc.)        *
    **************************************************************************/
    builder.Services
        .AddIdentityApiEndpoints<IdentityUser>()
        .AddEntityFrameworkStores<ShareMemoriesContext>()
        .AddApiEndpoints();

    /*************************************************************************
    *                       Add Bearer JWT Authentication                    *
    **************************************************************************/
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

    }).AddJwtBearer(options =>
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetSection("Jwt:Key").Value))
        };
    });

    ///*************************************************************************
    //*                           Add Password strength                        *
    //**************************************************************************/
    //builder.Services.AddIdentity<ExtendIdentityUser, IdentityRole>(options =>
    //{
    //    // for e.g. P@ssw0rd
    //    options.Password.RequiredLength = 8;
    //    options.Password.RequireNonAlphanumeric = true; // for e.g. !"£$%^
    //    options.Password.RequireDigit = true;
    //    options.Password.RequireLowercase = true;
    //    options.Password.RequireUppercase = true;

    //}).AddEntityFrameworkStores<ShareMemoriesContext>()
    //    .AddDefaultTokenProviders();

    /*************************************************************************
    *               Add Authorization & Authentication                       *
    **************************************************************************/
    builder.Services.AddAuthorization();
    //builder.Services.AddAuthentication();

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    var app = builder.Build();

    /*************************************************************************
    *                       Register Minimal APIEndpoints                    *
    **************************************************************************/
    app.MapPictureEndpoints();
    app.MapVideoEndpoints();
    //app.MapAuthEndpoints();

    /*************************************************************************
    *                 Custom ProblemDetails Error Handler                    *
    **************************************************************************/
    //app.UseExceptionHandler(); // apply custom error handler, comment out if you want to see full stack trace


    /*************************************************************************
    *                               Add Identity                             *
    **************************************************************************/
    app.MapIdentityApi<IdentityUser>();

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

    ///*************************************************
    ///* Apply security middleware 
    //*************************************************/
    app.UseAuthentication();
    app.UseAuthorization();

    // Test authentication API when logged in
    app.MapGet("/testAuthenticationWhenLoggedIn", (ClaimsPrincipal user) => $"Hello {user.Identity!.Name}").RequireAuthorization();

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
