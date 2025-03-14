﻿using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.OpenApi.Models;
using ShareMemories.API.Validators;
using ShareMemories.Application.Interfaces;

namespace ShareMemories.API.Endpoints.Picture
{
    public static class PictureEndpoints
    {
        public static void MapPictureEndpoints(this IEndpointRouteBuilder routes)
        {
            // apply settings to a group of API's (default to Bearer Authentication & associate a Policy with all API calls)
            var group = routes.MapGroup("pictures")
              .WithOpenApi()
              .RequireAuthorization("UserPolicy") // apply a security policy to API's and a default Bearer Scheme
              .WithMetadata(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme })
                ;

            // API below is returning a Typed Result of 'Book' or 'NotFound', depending on if the book is retrieved. Authorisation needed.
            group.MapGet("/PictureAsync/{id}", [OutputCache(PolicyName = "Expire30")] async Task<Results<Ok<ShareMemories.Domain.Entities.Picture>, NotFound>> (IPictureService pictureService, int id) =>
            {
                // apply guard rules to individual property's - not FluentValidator in this case!
                Guard.Against.Null(id, nameof(id), "Id must not be Null");
                Guard.Against.NegativeOrZero(id, nameof(id), "Id must be greater than zero");

                return await pictureService.GetPictureByIdAsync(id) is { } picture // pattern matching expression. Checking if bookService.GetBook(id) matches the pattern { } and assigns it to a variable named book.
                        ? TypedResults.Ok(picture) // return Book if non-null value
                        : TypedResults.NotFound(); // if Null, return NotFound
            })
              .WithName("GetPictureById")
              .WithOpenApi(x => new OpenApiOperation(x)
              {
                  Summary = "Retrieve a picture by the picture Id",
                  Description = "Returns information about a selected picture from the user's library.",
                  Tags = new List<OpenApiTag> { new() { Name = "Pictures API Library" } }
              })
              .CacheOutput(x => x.Tag("PictureById")); // invalidate data when new record added, by using tag in Post API    
              //.RequireCors("AllowSpecificOrigins"); // apply to individual API's or use global 'app.UseCors("AllowSpecificOrigins");' in programs.cs


            group.MapPost("/InsertPictureAsync", async (HttpContext context, ShareMemories.Domain.Entities.Picture picture, IPictureService pictureService) =>
            {
                // DTO validated before this line, using "PictureValidator"
                var insertedPicture = await pictureService.InsertPictureAsync(picture);

                // Return 200 OK with the inserted picture or 404 Not Found if insertion fails
                return insertedPicture.Id > 0
                    ? Results.Ok(insertedPicture)
                    : Results.NotFound("Not able to insert picture.");

            })
           .WithName("InsertPictureAsync")
           .WithOpenApi(x => new OpenApiOperation(x)
           {
               Summary = "Insert a new picture",
               Description = "Adds a new picture to database",
               Tags = new List<OpenApiTag> { new() { Name = "Pictures API Library" } }
           })
           .CacheOutput(x => x.Tag("PictureById"))
           .AddEndpointFilter<GenericValidationFilter<PictureValidator, ShareMemories.Domain.Entities.Picture>>(); // apply fluent validation to DTO model from client and pass back broken rules    

            group.MapGet("/GetAllUserPicturesByUserId", [OutputCache(PolicyName = "Expire30")] Results<Ok<List<ShareMemories.Domain.Entities.Picture>>, NotFound> (IPictureService pictureService, int id) =>
            {
                return pictureService.GetPictures() is { } picture // pattern matching expression. Checking if bookService.GetBook(id) matches the pattern { } and assigns it to a variable named book.
                       ? TypedResults.Ok(picture) // return Book if non-null value
                       : TypedResults.NotFound(); // if Null, return NotFound                
            })
            .WithName("RetrieveAllUserPicturesByUserId")
             .WithOpenApi(x => new OpenApiOperation(x)
             {
                 Summary = "Retrieve all pictures by user Id",
                 Description = "Returns information about a selected picture from the user's library.",
                 Tags = new List<OpenApiTag> { new() { Name = "Pictures API Library" } }
             });

            group.MapPut("/UpdatePictureAsync", async (HttpContext context, ShareMemories.Domain.Entities.Picture picture, IPictureService pictureService) =>
            {
                return "Picture updated...";
            })
           .WithName("UpdatePictureAsync")
           .WithOpenApi(x => new OpenApiOperation(x)
           {
               Summary = "Update picture",
               Description = "Updated information about a selected picture.",
               Tags = new List<OpenApiTag> { new() { Name = "Pictures API Library" } }
           });
        }
    }
}
