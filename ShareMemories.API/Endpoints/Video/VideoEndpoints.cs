using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;

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
                Summary = "Retrieve video by video Id",
                Description = "Returns information about a selected video from the user's library.",
                Tags = new List<OpenApiTag> { new() { Name = "Video API Library" } }
            });

            group.MapPost("/InsertVideoAsync", async (HttpContext context, ShareMemories.Domain.Entities.Video video, IVideoService videoService) =>
            {
                // DTO validated before this line, using "VideoValidator"
                var insertedVideo = await videoService.InsertVideoAsync(video);

                // Return 200 OK with the inserted Video or 404 Not Found if insertion fails
                return insertedVideo.Id > 0
                    ? Results.Ok(insertedVideo)
                    : Results.NotFound("Not able to insert video.");
            })
            .WithName("InsertVideoAsync")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Insert a new Video",
                Description = "Adds a new Video to database",
                Tags = new List<OpenApiTag> { new() { Name = "Video API Library" } }
            })
            .CacheOutput(x => x.Tag("VideoById"))
            .AddEndpointFilter<GenericValidationFilter<VideoValidator, ShareMemories.Domain.Entities.Video>>(); // apply fluent validation to DTO model from client and pass back broken rules    

            group.MapGet("/GetAllUserVideosByUserId", () =>
            {
                return "AllUserVideosByUserId Data...";
            })
            .WithName("RetrieveAllUserVideosByUserId")
            .WithOpenApi(x => new OpenApiOperation(x)
            {
                Summary = "Retrieve all videos based on user Id",
                Description = "Returns information about a selected video from the user's library.",
                Tags = new List<OpenApiTag> { new() { Name = "Video API Library" } }
            });

            group.MapPut("/UpdateVideoAsync", async (HttpContext context, ShareMemories.Domain.Entities.Video video, IVideoService pictureService) =>
            {
                return "Video updated...";
            })
        .WithName("UpdateVideoAsync")
         .WithOpenApi(x => new OpenApiOperation(x)
         {
             Summary = "Update video",
             Description = "Updated information about a selected video.",
             Tags = new List<OpenApiTag> { new() { Name = "Video API Library" } }
         });
        }
    }
}
