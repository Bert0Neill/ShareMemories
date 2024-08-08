using ShareMemories.Domain.Entities;

namespace ShareMemories.Endpoints.User
{
    public static class UsersEndpoints
    {
        public static void RegisterUserEndpoints(this IEndpointRouteBuilder routes)
        {
            //var users = routes.MapGroup("/api/v1/users");

            var group = routes.MapGroup("users")
                .WithOpenApi()
                //.RequireAuthorization()
                ;

            group.MapGet("", () => Collections.Users)
            .WithName("GetAllUsers")
                 .Produces<List<ShareMemories.Domain.Entities.User>>(StatusCodes.Status200OK);

            group.MapGet("/{id:int}", (int id) =>
            {
                var user = Collections.Users.FirstOrDefault(user => user.Id == id);
                return user is not null ? Results.Ok(user) : Results.NotFound();
            })
            .WithName("GetUserById")
            .Produces< ShareMemories.Domain.Entities.User >(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            group.MapPost("", (ShareMemories.Domain.Entities.User user) =>
            {
                Collections.Users.Add(user);
                return Results.Created($"/api/v1/users/{user.Id}", user);
            })
            .WithName("CreateUser")
            .Produces<ShareMemories.Domain.Entities.User>(StatusCodes.Status201Created);

            group.MapPut("/{id:int}", (int id, ShareMemories.Domain.Entities.User updatedUser) =>
            {
                var currentUser = Collections.Users.FirstOrDefault(user => user.Id == id);
                if (currentUser is null) return Results.NotFound();

                currentUser.Firstname = updatedUser.Firstname;
                currentUser.Lastname = updatedUser.Lastname;
                currentUser.BirthDate = updatedUser.BirthDate;

                return Results.NoContent();
            })
            .WithName("UpdateUser")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status404NotFound);

            group.MapDelete("/{id:int}", (int id) =>
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
        public static List<ShareMemories.Domain.Entities.User> Users { get; set; } = new List<ShareMemories.Domain.Entities.User>();
    }
}
