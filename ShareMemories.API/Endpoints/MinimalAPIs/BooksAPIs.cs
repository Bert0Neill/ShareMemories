using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi.Models;
using ShareMemories.Domain.Models;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.API.Endpoints.MinimalAPIs
{
    public class BooksAPIs
    {
        private readonly WebApplication app;

        public BooksAPIs(WebApplication webApp) => app = webApp;

        public void RegisterBooksAPI()
        {
            // API below is returning a Typed Result of 'Book' or 'NotFound', depending on if the book is retrieved. Authorisation needed.
            app.MapGet("/books/{id}", Results<Ok<Book>, NotFound> (IBookService bookService, int id) =>
            {
                // apply guard rules to individual property's - not FluentValidator in this case!
                Guard.Against.Null(id, nameof(id), "Id must not be Null");
                Guard.Against.NegativeOrZero(id, nameof(id), "Id must be greater than zero");

                return bookService.GetBook(id) is { } book // pattern matching expression. Checking if bookService.GetBook(id) matches the pattern { } and assigns it to a variable named book.
                        ? TypedResults.Ok(book) // return Book if non-null value
                        : TypedResults.NotFound(); // if Null, return NotFound
            })
              .RequireAuthorization()
              .WithName("GetBookById")
              .WithOpenApi(x => new OpenApiOperation(x)
              {
                  Summary = "Get Library Book By Id",
                  Description = "Returns information about selected book from the Amy's library.",
                  Tags = new List<OpenApiTag> { new() { Name = "Version1 API Library" } }
              })
              //.CacheOutput(x => x.SetVaryByQuery("id")) // cache by paramater used (NB looks to be the default)
              .CacheOutput(x => x.Tag("BooksById")); // invalidate data when new record added, by using tag in Post API              

            // authorisation needed
            app.MapGet("/books", (IBookService bookService) =>
                TypedResults.Ok(bookService.GetBooks()))
                .RequireAuthorization()
                .WithName("GetBooks")
                .WithOpenApi(x => new OpenApiOperation(x)
                {
                    Summary = "Get Library Books",
                    Description = "Returns information about all the available books from the Amy's library.",
                    Tags = new List<OpenApiTag> { new() { Name = "Version1 API Library" } } // group API's 
                });

            // no authorisation needed
            app.MapGet("/books-NoAuth", (IBookService bookService) =>
                TypedResults.Ok(bookService.GetBooks()))                
                .WithName("books-NoAuth")
                .WithOpenApi(x => new OpenApiOperation(x)
                {
                    Summary = "Get v3 Library Books",
                    Description = "Returns information about all the available books from the Amy's library.",
                    Tags = new List<OpenApiTag> { new() { Name = "Version2 API Library" } } // group API's 
                });

            app.MapGet("/throwException", (IBookService bookService) => bookService.ThrowException())
              .RequireAuthorization()
              .WithName("ThrowException")
              .WithOpenApi(x => new OpenApiOperation(x)
              {
                  Summary = "Test exception handling",
                  Description = "Returns information about all the available books from the Amy's library.",
                  Tags = new List<OpenApiTag> { new() { Name = "Version2 API Library" } } // group API's 
              });
        }
    }
}
