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
    builder.Services.AddCORsServices(builder.Configuration, logger); // CORs service - restrict Cross Origin Requests to your API's (I'm applying tpo all API's, but you can be more granular)

    // use extension methods to configure JWT, DI, Security Policy, Response caching, DbContext, Error middleware, DTO validation, CORs & Swagger
    builder.Services.AddServicesInitialSetup(builder.Configuration, logger);
    builder.Services.AddServicesJwtIdentity(builder.Configuration, logger);
    builder.Services.AddCustomServicesSwagger(builder.Configuration, logger); // configure Swagger for JWT Bearer testing

    var app = builder.Build();

    // use extension methods to configure application middleware and custom endpoints
    app.ConfigureMiddleware(app.Environment);
    app.ConfigureEndpoints();

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
