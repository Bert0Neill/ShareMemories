using Microsoft.OpenApi.Models;

namespace ShareMemories.API.Endpoints.Video
{
    public static class VideoEndpoints
    {

        public static void MapVideoEndpoints(this IEndpointRouteBuilder app)
        {
            // NB: what you apply to group is applied to all API's in that group
            var group = app.MapGroup("Video")
                .WithOpenApi()
                //.RequireAuthorization()
                ;

            group.MapGet("/GetVideoById", () =>
            {
                return "GetVideoById Data...";
            })
            .WithName("RetrieveVideoById")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Get Picture By Id",
                Description = "Returns information about a selected video from the user's library.",
                Tags = new List<OpenApiTag> { new() { Name = "Video API Library" } }
            });

            group.MapGet("/GetAllUserVideosByUserId", () =>
            {
                return "AllUserVideosByUserId Data...";
            })
            .WithName("RetrieveAllUserVideosByUserId")
                        .WithOpenApi(x => new OpenApiOperation(x)
                        {
                            Summary = "Get Picture By Id",
                            Description = "Returns information about a selected video from the user's library.",
                            Tags = new List<OpenApiTag> { new() { Name = "Video API Library" } }
                        });


            group.MapPost("/ShareVideoById", () =>
            {
                return "ShareVideoByIdData...";
            })
            .WithName("ShareVideoById")
                        .WithOpenApi(x => new OpenApiOperation(x)
                        {
                            Summary = "Get Picture By Id",
                            Description = "Returns information about a selected video from the user's library.",
                            Tags = new List<OpenApiTag> { new() { Name = "Video API Library" } }
                        });

        }
    }
}
