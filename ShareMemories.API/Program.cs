using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using NLog;
using ShareMemories.API.Extensions;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
var logger = NLog.LogManager.Setup().LoadConfigurationFromFile("nlog.config").GetCurrentClassLogger();

try
{
    // use extension methods to configure JWT, DI, Security Policy, Response caching, DbContext, Error middleware, DTO validation & Swagger
    builder.Services.AddCustomServices(builder.Configuration, logger);
    builder.Services.AddCustomServicesSwagger(builder.Configuration, logger);

    builder.Services.AddAuthorization();
    
    var app = builder.Build();

    // use extension methods to configure middleware and endpoints
    app.ConfigureMiddleware(app.Environment);
    app.ConfigureEndpoints();


    // Test authentication API when logged in
    app.MapGet("/VerifyLoggedIn", (ClaimsPrincipal user) => $"Hello {user.Identity!.Name}")
        .RequireAuthorization("AdminPolicy")
        .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

    app.MapGet("/UserPolicy", () =>
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
