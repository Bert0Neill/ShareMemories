﻿// <auto-generated> This file has been auto generated by EF Core Power Tools. </auto-generated>
#nullable disable
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ShareMemories.Domain.Entities;

namespace ShareMemories.Infrastructure.Database;

// NB using 'IdentityDbContext' not 'DbContext' because of .net roles identity DB
public partial class ShareMemoriesContext : IdentityDbContext<ExtendIdentityUser>
{
    public ShareMemoriesContext(DbContextOptions options) : base(options) { }

    //Define our tables
    public DbSet<ExtendIdentityUser> ExtendedIdentityUsers { get; set; }

    public DbSet<Friendship> Friendships { get; set; }

    public DbSet<Picture> Pictures { get; set; }

    public DbSet<Video> Videos { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        /*
         * Drop-Database (doesn't drop database only tables etc.)
         * Add-Migration Seed (must have unique name parameter)
         * update-database (applies your migration script)
         */

        SeedRoles(modelBuilder);  // populate roles with start-up data        
        SeedUsers(modelBuilder);  // populate Users with start-up data
        SeedPictures(modelBuilder);  // populate Pictures with start-up data
        SeedVideos(modelBuilder);  // populate Videos with start-up data
        SeedFriendships(modelBuilder);  // populate Friendships with start-up data

        // Configure primary key for IdentityUserLogin
        modelBuilder.Entity<IdentityUserLogin<string>>()
            .HasKey(l => new { l.LoginProvider, l.ProviderKey, l.UserId });

        // Configure the primary key for IdentityUserRole
        modelBuilder.Entity<IdentityUserRole<string>>()
            .HasKey(ur => new { ur.UserId, ur.RoleId });

        modelBuilder.Entity<Picture>(entity =>
        {
            entity.ToTable("Picture");

            entity.Property(e => e.FriendlyName)
                .IsRequired()
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.IsArchived).HasDefaultValue(false);
            entity.Property(e => e.PictureBytes)
                .IsRequired()
                .HasColumnName("Picture");          
        });

        modelBuilder.Entity<Video>(entity =>
        {
            entity.ToTable("Video");

            entity.Property(e => e.FriendlyName)
                .IsRequired()
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.IsArchived).HasDefaultValue(false);
            entity.Property(e => e.IsWatched).HasDefaultValue(false);
            entity.Property(e => e.Url)
                .IsRequired()
                .HasMaxLength(100)
                .IsUnicode(false)
                .HasColumnName("URL");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);

    private void SeedRoles(ModelBuilder builder)
    {
        builder.Entity<IdentityRole>().HasData(
            new IdentityRole { Id = "1", Name = "Admin", NormalizedName = "ADMIN" },
            new IdentityRole { Id = "2", Name = "User", NormalizedName = "USER" },
            new IdentityRole { Id = "3", Name = "Qa", NormalizedName = "QA" }
        );
    }

    private void SeedUsers(ModelBuilder builder)
    {
        builder.Entity<ExtendIdentityUser>().HasData(
             new ExtendIdentityUser
             {
                 Id = "43a8cbb1-4e09-41de-9281-679f8ee3703a",
                 UserName = "string4",
                 NormalizedUserName = "STRING4",
                 Email = "user@example.com",
                 NormalizedEmail = "USER@EXAMPLE.COM",
                 EmailConfirmed = false,
                 PasswordHash = "AQAAAAIAAYagAAAAELNSkTanLtE35z4s/YMe2pks+t6xCd7UZfZyduBMcuxJPopgdEcYmQdUhhPr/PDotg==",
                 SecurityStamp = "M646EOPZA5FUTBWNHGGQSH7C7K7GPTY6",
                 ConcurrencyStamp = "68f8a171-8d55-4196-8bff-8dbb76237385",
                 PhoneNumber = null,
                 PhoneNumberConfirmed = false,
                 TwoFactorEnabled = false,
                 LockoutEnd = null,
                 LockoutEnabled = true,
                 AccessFailedCount = 0,
                 DateOfBirth = DateOnly.FromDateTime(DateTime.Now),
                 FirstName = "Jane",
                 LastName = "Bloggs"
             },
             new ExtendIdentityUser
             {
                 Id = "af327f76-e5c4-43a4-8590-e8bd355003f2",
                 UserName = "string13456",
                 NormalizedUserName = "STRING13456",
                 Email = "user@example6.com",
                 NormalizedEmail = "USER@EXAMPLE6.COM",
                 EmailConfirmed = false,
                 PasswordHash = "AQAAAAIAAYagAAAAEFr0LgSGpJNLW6YLQN9Z7sjtmW3LEIjO5wIxGul5maQd3A4zD9CqOAqsBbiQ8m4Xag==",
                 SecurityStamp = "G2UNOKQAHAAQL33PYMQ7IAC724OPCY3G",
                 ConcurrencyStamp = "c772f240-6771-4ef5-b7a8-6c316ab651ad",
                 PhoneNumber = null,
                 PhoneNumberConfirmed = false,
                 TwoFactorEnabled = false,
                 LockoutEnd = null,
                 LockoutEnabled = true,
                 AccessFailedCount = 0,
                 DateOfBirth = DateOnly.FromDateTime(DateTime.Now),
                 FirstName = "Joe",
                 LastName = "Bloggs"
             }
         );
    }
    private void SeedVideos(ModelBuilder builder)
    {
        builder.Entity<Video>().HasData(
            new Video
            {Id = 1,
                UserId = 1,
                FriendlyName = "My video 1",
                Url = "https://www.youtube.com/watch?v=-wtIMTCHWuI",
                IsWatched = false,
                IsArchived = false
            },
            new Video
            {Id = 2,
                UserId = 2,
                FriendlyName = "My video 4",
                Url = "http://youtube.com/watch?v=-wtIMTCHWuI",
                IsWatched = true,
                IsArchived = false
            },
            new Video
            {Id = 3,
                UserId = 1,
                FriendlyName = "My video 3",
                Url = "http://m.youtube.com/watch?v=-wtIMTCHWuI",
                IsWatched = false,
                IsArchived = false
            },
            new Video
            {
                Id = 4,
                UserId = 4,
                FriendlyName = "My video 5",
                Url = "https://www.youtube.com/watch?v=lalOy8Mbfdc",
                IsWatched = true,
                IsArchived = false
            }
        );
    }

    private void SeedPictures(ModelBuilder builder)
    {
        builder.Entity<Picture>().HasData(
             new Picture
             {
                 Id = 1,
                 UserId = 1,
                 FriendlyName = "My picture 1",
                 PictureBytes = Convert.FromBase64String("aW1hZ2VfZGF0YV8x"), // "image_data_1" as base64
                 IsArchived = false
             },
             new Picture
             {
                 Id = 2,
                 UserId = 1,
                 FriendlyName = "My picture 2",
                 PictureBytes = Convert.FromBase64String("aW1hZ2VfZGF0YV8y"), // "image_data_2" as base64
                 IsArchived = false
             },
             new Picture
             {
                 Id = 3,
                 UserId = 2,
                 FriendlyName = "My picture 3",
                 PictureBytes = Convert.FromBase64String("aW1hZ2VfZGF0YV8z"), // "image_data_3" as base64
                 IsArchived = false
             },
             new Picture
             {
                 Id = 4,
                 UserId = 4,
                 FriendlyName = "My picture 4",
                 PictureBytes = Convert.FromBase64String("aW1hZ2VfZGF0YV80"), // "image_data_4" as base64
                 IsArchived = false
             }
         );
    }

    private void SeedFriendships(ModelBuilder builder)
    {
        // Seed data for Friendships table
        builder.Entity<Friendship>().HasData(
            new Friendship { Id = 1, UserId = 1, FriendsWithId = 2, IsArchived = false },
            new Friendship { Id = 2, UserId = 2, FriendsWithId = 1, IsArchived = false },
            new Friendship { Id = 3, UserId = 3, FriendsWithId = 4, IsArchived = false },
            new Friendship { Id = 4, UserId = 4, FriendsWithId = 3, IsArchived = false }
        );
    }
}