using Serilog;
using ShareMemories.API.Extensions.AppBuilder;
using ShareMemories.API.Extensions.ServiceBuilder;
using ShareMemories.API.Middleware;

var builder = WebApplication.CreateBuilder(args);

try
{
    // configure using extensions, to keep programs.cs lean
    builder.Services.AddServicesLogging(builder); // create logger        
    builder.Services.AddCORsServices(builder.Configuration); // CORs service - restrict Cross Origin Requests to your API's (I'm applying tpo all API's, but you can be more granular)
    builder.Services.AddServicesInitialSetup(builder.Configuration); // DI, Caching, DbContext, DTO validation
    builder.Services.AddServicesJwtIdentity(builder.Configuration); // configure JWT, Policys etc.
    builder.Services.AddCustomServicesSwagger(builder.Configuration); // configure Swagger for JWT Bearer testing

    var app = builder.Build();

    // use extension methods to configure application middleware and custom endpoints
    app.ConfigureMiddleware(app.Environment);
    app.ConfigureEndpoints();

    // Register logging middleware - automatically log all method (you still make individual logs, like error handling - a separate log is created for your logs)
    app.UseMiddleware<MethodLoggingMiddleware>(); 

    app.Run();
}
catch (Exception exception)
{        
    Log.Logger.Error(exception,"Stopped program because of exception");
    throw;
}
