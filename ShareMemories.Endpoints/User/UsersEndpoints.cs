
using System;

namespace ShareMemories.Endpoints.User
{
    public static class ProductsModule
    {
        public static void RegisterProductsEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/products", async (AppDbContext dbContext) =>
            {
                return Results.Ok(await dbContext.Products.ToListAsync());
            });

            endpoints.MapPost("/products", async (Product product, AppDbContext dbContext) =>
            {
                dbContext.Products.Add(product);

                await dbContext.SaveChangesAsync();

                return Results.Ok(product);
            });
        }
    }
    //public static class UsersEndpoints
    //{
    //    public static void RegisterUserEndpoints(this IEndpointRouteBuilder routes)
    //    {
    //        var users = routes.MapGroup("/api/v1/users");

    //        users.MapGet("", () => Collections.Users);

    //        users.MapGet("/{id}", (int id) => Collections.Users
    //                                                     .FirstOrDefault(user => user.Id == id));

    //        users.MapPost("", (Data.User user) => Collections.Users.Add(user));

    //        users.MapPut("/{id}", (int id, Data.User user) =>
    //        {
    //            Data.User currentUser = Collections.Users
    //                                          .FirstOrDefault(user => user.Id == id);

    //            currentUser.FirstName = user.FirstName;
    //            currentUser.LastName = user.LastName;
    //            currentUser.BirthDate = user.BirthDate;
    //        });

    //        users.MapDelete("/{id}", (int id) =>
    //        {
    //            var userForDeletion = Collections.Users
    //                                             .FirstOrDefault(user => user.Id == id);

    //            Collections.Users.Remove(userForDeletion);
    //        });
    //    }
    //}
}
