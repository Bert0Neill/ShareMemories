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
            .WithOpenApi();

            group.MapGet("/GetAllUserVideosByUserId", () =>
            {
                return "AllUserVideosByUserId Data...";
            })
            .WithName("RetrieveAllUserVideosByUserId")
            .WithOpenApi();

            group.MapPost("/ShareVideoById", () =>
            {
                return "ShareVideoByIdData...";
            })
            .WithName("ShareVideoById")
            .WithOpenApi();
        }
    }
}
