using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using NLog;
using ShareMemories.API.Extensions.AppBuilder;
using ShareMemories.API.Extensions.ServiceBuilder;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
var logger = NLog.LogManager.Setup().LoadConfigurationFromFile("nlog.config").GetCurrentClassLogger();

try
{
    builder.Logging.AddConsole(); // Add console logging


    //builder.Services.AddCORsServices(builder.Configuration, logger);

    // configure CORS
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowSpecificOrigins",
            policyBuilder =>
            {
                // apply the allowed origins from the configuration
                policyBuilder.WithOrigins("https://localhost:7273")
                             .AllowAnyMethod() // Allow all HTTP methods
                             .AllowAnyHeader() // Allow all headers
                                               //.AllowCredentials(); // Allow credentials (cookies)
                             ;
            });
    });

    builder.Services.AddCors();

    // use extension methods to configure JWT, DI, Security Policy, Response caching, DbContext, Error middleware, DTO validation, CORs & Swagger
    builder.Services.AddCustomServices(builder.Configuration, logger);
    builder.Services.AddCustomServicesSwagger(builder.Configuration, logger);
    
    

    var app = builder.Build();

    //app.UseCors("AllowSpecificOrigins"); // apply the CORS policy
    //app.UseCors("AllowSpecificOrigins"); // apply the CORS policy
    //app.UseCors(builder => builder.AllowAnyHeader().AllowAnyMethod().WithOrigins("http://MyValidDomain.com"));

    // use extension methods to configure middleware and custom endpoints
    app.ConfigureMiddleware(app.Environment);
    app.ConfigureEndpoints();

    

    /****************************************************************************************************************
     *                                      Testing API's                                                           *
     ****************************************************************************************************************/
    app.MapGet("/AdminLoggedIn", (ClaimsPrincipal user) => $"Hello {user.Identity!.Name}")
        .RequireAuthorization("AdminPolicy")
        .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

    app.MapGet("/UserLoggedIn", () =>
    {
        return Results.Ok("This data is accessible by User");
    })
    .RequireAuthorization("UserPolicy")
    .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });
    

    app.Run();
}
catch (Exception exception)
{    
    logger.Error(exception, "Stopped program because of exception");
    throw;
}
finally
{
    // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
    NLog.LogManager.Shutdown();
}
