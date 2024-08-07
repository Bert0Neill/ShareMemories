using ShareMemories.API.Endpoints.Picture;
using ShareMemories.API.Endpoints.Video;
using ShareMemories.API.Endpoints.Weather;
using ShareMemories.API.Extensions;

var builder = WebApplication.CreateBuilder(args);

/*************************************************************************
* Associate a Global Error handler middleware for your end-points        *
**************************************************************************/
builder.Services.AddProblemDetails(); // add ProblemDetails handler - consistent error response
builder.Services.AddExceptionHandler<ExceptionToProblemDetailsHandler>(); // notify services of your custom error handling, by using "app.UseExceptionHandler()" you are telling the system to use it

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

/*************************************************************************
*                       Dependency Injection                             *
**************************************************************************/
//builder.Services.AddTransient<IDistributedService, SqlServerDistributedService>(); // DI service class
//builder.Services.AddDbContext<SqlServerEmployeeDatabaseContext>(); // DI database context

var app = builder.Build();

/*************************************************************************
*                       Register Minimal APIEndpoints                    *
**************************************************************************/
app.MapWeatherEndpoints(); // add custom endpoints
app.MapPictureEndpoints();
app.MapVideoEndpoints();


/*************************************************************************
*                 Custom ProblemDetails Error Handler                    *
**************************************************************************/
//app.UseExceptionHandler(); // apply custom error handler, comment out if you want to see full stack trace


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.Run();
