namespace ShareMemories.API.Extensions
{
    public static class Configuration
    {
        public static void RegisterServices(this WebApplicationBuilder builder)
        {
            builder.Services
                   .AddEndpointsApiExplorer()
                   .AddSwaggerGen();
        }

        public static void RegisterMiddlewares(this WebApplication app)
        {
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger()
                   .UseSwaggerUI();
            }

            app.UseHttpsRedirection();
        }
    }
}
