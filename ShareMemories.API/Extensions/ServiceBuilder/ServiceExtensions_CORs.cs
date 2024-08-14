namespace ShareMemories.API.Extensions.ServiceBuilder
{
    public static class ServiceExtensions_CORs
    {
        public static void AddCORsServices(this IServiceCollection services, IConfiguration configuration, NLog.Logger logger)
        {
            // retrieve the list of allowed origins from the configuration
            var corsWhitelistedDomains = configuration.GetSection("CORsWhitelistedDomains").Get<string[]>();

            // configure CORS
            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigins",
                    policyBuilder =>
                    {
                        // apply the allowed origins from the configuration
                        policyBuilder.WithOrigins(corsWhitelistedDomains)
                                     .AllowAnyMethod() // Allow all HTTP methods
                                     .AllowAnyHeader() // Allow all headers
                                     .AllowCredentials(); // Allow credentials (cookies)
                    });
            });

            services.AddCors();
        }
    }
}
