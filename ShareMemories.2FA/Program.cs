using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

//private readonly UserManager<IdentityUser> _userManager;
//private readonly SignInManager<IdentityUser> _signInManager;
//private readonly RoleManager<IdentityRole> _roleManager;
//private readonly IEmailService _emailService;
//private readonly IConfiguration _configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender, EmailSender>(); // Implement EmailSender
builder.Services.AddAuthorization();
builder.Services.AddAuthentication();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/2fa/create", async (UserManager<IdentityUser> userManager, IEmailSender emailSender, string username) =>
{
    var user = await userManager.FindByNameAsync(username);
    if (user == null)
    {
        return Results.NotFound("User not found.");
    }

    var token = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
    await emailSender.SendEmailAsync(user.Email, "Your 2FA Code", $"Your two-factor authentication code is: {token}");

    return Results.Ok("2FA code sent.");
});

app.MapPost("/2fa/verify", async (UserManager<IdentityUser> userManager, string username, string code) =>
{
    var user = await userManager.FindByNameAsync(username);
    if (user == null)
    {
        return Results.NotFound("User not found.");
    }

    var isValid = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, code);
    if (!isValid)
    {
        return Results.BadRequest("Invalid 2FA code.");
    }

    return Results.Ok("2FA verified successfully.");
});

app.Run();

class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
}

public class EmailSender : IEmailSender
{
    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        // Implement your email sending logic here
        Console.WriteLine($"Email sent to {email} with subject {subject}");
        Console.WriteLine(htmlMessage);
        return Task.CompletedTask;
    }
}