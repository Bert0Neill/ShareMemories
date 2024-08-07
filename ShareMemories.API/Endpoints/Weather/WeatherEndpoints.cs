using ShareMemories.API.Models;
using System.ComponentModel.Design;

namespace ShareMemories.API.Endpoints.Weather
{

    public static class WeatherEndpoints
    {
        public static void MapWeatherEndpoints(this IEndpointRouteBuilder app)
        {
            var summaries = new[] { "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching" };

            // NB: what you apply to group is applied to all API's in that group
            var group = app.MapGroup("weather")
                .WithOpenApi()
                //.RequireAuthorization()
                ;

            group.MapGet("/hello", () => "Hello, World!")
                .WithName("HelloEndpoint")
                .Produces<string>(StatusCodes.Status200OK);

            group.MapGet("/weatherforecast", () =>
            {
                //throw new Exception("Bad fata");

                var forecast = Enumerable.Range(1, 5).Select(index =>
                    new WeatherForecast
                    (
                        DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                        Random.Shared.Next(-20, 55),
                        summaries[Random.Shared.Next(summaries.Length)]
                    ))
                    .ToArray();
                return forecast;
            })
            .WithName("GetWeatherForecast")
            .WithOpenApi();

        }

        internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
        {
            public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
        }
    }
}