namespace ShareMemories.API.Endpoints.Picture
{
    public static class PictureEndpoints
    {
        public static void MapPictureEndpoints(this IEndpointRouteBuilder app)
        {
            app.MapGet("/GetPictureById", () =>
            {
                return "GetPictureById Data...";
            })
            .WithName("RetrievePictureById")
            .WithOpenApi();

            app.MapGet("/GetAllUserPicturesByUserId", () =>
            {
                return "AllUserPicturesByUserId Data...";
            })
            .WithName("RetrieveAllUserPicturesByUserId")
            .WithOpenApi();

            app.MapPost("/SharePictureById", () =>
            {
                return "SharePictureByIdData...";
            })
            .WithName("SharePictureById")
            .WithOpenApi();
        }
    }
}
