using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Endpoints.Auth;
using ShareMemories.API.Endpoints.MinimalAPIs;
using ShareMemories.API.Endpoints.Picture;
using ShareMemories.API.Endpoints.Video;
using ShareMemories.API.Endpoints.Weather;
using ShareMemories.API.Extensions;
using ShareMemories.Application.Interfaces;
using ShareMemories.Application.InternalServices;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.Interfaces;
using ShareMemories.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

var logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

try
{
    /*************************************************************************
    * Associate a Global Error handler middleware for your end-points        *
    **************************************************************************/
    builder.Services.AddProblemDetails(); // add ProblemDetails handler - consistent error response
    builder.Services.AddExceptionHandler<ExceptionToProblemDetailsHandler>(); // notify services of your custom error handling, by using "app.UseExceptionHandler()" you are telling the system to use it

    /*************************************************************************
    *           Register DbContext and provide ConnectionString              *
    **************************************************************************/
    builder.Services.AddDbContext<ShareMemoriesContext>(db => db.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")), ServiceLifetime.Singleton);

    /*************************************************************************
    *                       Dependency Injection                             *
    **************************************************************************/
    //builder.Services.AddTransient<IDistributedService, SqlServerDistributedService>(); // DI service class
    builder.Services.AddScoped<IPictureService, PictureService>();
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

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    var app = builder.Build();

    /*************************************************************************
    *                       Register Minimal APIEndpoints                    *
    **************************************************************************/
    app.MapWeatherEndpoints();
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
    // app.MapIdentityApi<IdentityUser>();

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
    //app.UseAuthentication();
    //app.UseAuthorization();

    ///*************************************************
    //* Exposed public end-points
    //*************************************************/
    //new BooksAPIs(app).RegisterBooksAPI();
    //new LoginRegisterAPIs(app).RegisterLoginAPI();

    


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
