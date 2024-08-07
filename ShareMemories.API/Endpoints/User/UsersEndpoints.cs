
namespace ShareMemories.Endpoints.User
{
    public static class UsersEndpoints
    {
        public static void RegisterUserEndpoints(this IEndpointRouteBuilder routes)
        {
            var users = routes.MapGroup("/api/v1/users");

            users.MapGet("", () => Collections.Users)
            .WithName("GetAllUsers")
                 .Produces<List<ShareMemories.API.Models.User>>(StatusCodes.Status200OK);

            users.MapGet("/{id:int}", (int id) =>
            {
                var user = Collections.Users.FirstOrDefault(user => user.Id == id);
                return user is not null ? Results.Ok(user) : Results.NotFound();
            })
            .WithName("GetUserById")
            .Produces<ShareMemories.API.Models.User>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            users.MapPost("", (ShareMemories.API.Models.User user) =>
            {
                Collections.Users.Add(user);
                return Results.Created($"/api/v1/users/{user.Id}", user);
            })
            .WithName("CreateUser")
            .Produces<ShareMemories.API.Models.User>(StatusCodes.Status201Created);

            users.MapPut("/{id:int}", (int id, ShareMemories.API.Models.User updatedUser) =>
            {
                var currentUser = Collections.Users.FirstOrDefault(user => user.Id == id);
                if (currentUser is null) return Results.NotFound();

                currentUser.FirstName = updatedUser.FirstName;
                currentUser.LastName = updatedUser.LastName;
                currentUser.BirthDate = updatedUser.BirthDate;

                return Results.NoContent();
            })
            .WithName("UpdateUser")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status404NotFound);

            users.MapDelete("/{id:int}", (int id) =>
            {
                var userForDeletion = Collections.Users.FirstOrDefault(user => user.Id == id);
                if (userForDeletion is null) return Results.NotFound();

                Collections.Users.Remove(userForDeletion);
                return Results.NoContent();
            })
            .WithName("DeleteUser")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status404NotFound);
        }
    }

    public static class Collections
    {
        public static List<API.Models.User> Users { get; set; } = new List<API.Models.User>();
    }
}
