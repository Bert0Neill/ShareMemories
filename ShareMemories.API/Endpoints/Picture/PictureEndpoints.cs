using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.OpenApi.Models;
using ShareMemories.Application.Interfaces;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.API.Endpoints.Picture
{
    public static class PictureEndpoints
    {
        public static void MapPictureEndpoints(this IEndpointRouteBuilder routes)
        {
            // IPictureService


            var group = routes.MapGroup("pictures")
              .WithOpenApi()
              //.RequireAuthorization()
              ;

            //app.MapGet("/GetEmployeeByName/{employeeName}", [OutputCache(PolicyName = "Expire30")]
            // API below is returning a Typed Result of 'Book' or 'NotFound', depending on if the book is retrieved. Authorisation needed.
            //group.MapGet("/picture/{id}", Results<Ok<ShareMemories.Domain.Entities.Picture>, NotFound> (IPictureService pictureService, int id) =>
            //group.MapGet("/picture/{id}", Results<Ok<ShareMemories.Domain.Entities.Picture>, NotFound> (IPictureService pictureService, int id) =>
            group.MapGet("/picture/{id}", [OutputCache(PolicyName = "Expire30")] Results<Ok<ShareMemories.Domain.Entities.Picture>, NotFound> (IPictureService pictureService, int id) =>
            {
                // apply guard rules to individual property's - not FluentValidator in this case!
                Guard.Against.Null(id, nameof(id), "Id must not be Null");
                Guard.Against.NegativeOrZero(id, nameof(id), "Id must be greater than zero");

                return pictureService.GetPicture(id) is { } picture // pattern matching expression. Checking if bookService.GetBook(id) matches the pattern { } and assigns it to a variable named book.
                        ? TypedResults.Ok(picture) // return Book if non-null value
                        : TypedResults.NotFound(); // if Null, return NotFound
            })
              //.RequireAuthorization()
              .WithName("GetPictureById")
              .WithOpenApi(x => new OpenApiOperation(x)
              {
                  Summary = "Get Picture By Id",
                  Description = "Returns information about a selected picture from the user's library.",
                  Tags = new List<OpenApiTag> { new() { Name = "SharedMemories API Library" } }
              })
                  .CacheOutput(x => x.SetVaryByQuery("id")); // cache by parameter used (NB looks to be the default)
                                                //.CacheOutput(x => x.Tag("PictureById")); // invalidate data when new record added, by using tag in Post API    


            group.MapGet("/GetAllUserPicturesByUserId", () =>
            {
                return "AllUserPicturesByUserId Data...";
            })
            .WithName("RetrieveAllUserPicturesByUserId")
            .WithOpenApi();

            group.MapPost("/SharePictureById", () =>
            {
                return "SharePictureByIdData...";
            })
            .WithName("SharePictureById")
            .WithOpenApi();
        }
    }
}
