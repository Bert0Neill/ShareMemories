using Serilog;

namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensionsBuilder_Logging
    {
        public static void AddServicesLogging(this IServiceCollection services, WebApplicationBuilder builder)
        {
            // Configure Serilog
            builder.Services.AddSerilog(lc => lc
                .WriteTo.Console()
                .ReadFrom.Configuration(builder.Configuration));

            // Load configuration from appsettings.json
            Log.Logger = new LoggerConfiguration()
            .ReadFrom.Configuration(builder.Configuration)
            .CreateLogger();

            // Clear default logging providers and use Serilog
            builder.Logging.ClearProviders();
            builder.Logging.AddSerilog();
        }
    }
}
