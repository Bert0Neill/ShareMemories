﻿// <auto-generated> This file has been auto generated by EF Core Power Tools. </auto-generated>
#nullable disable
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ShareMemories.Domain.Entities;
using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Database;

// NB using 'IdentityDbContext' not 'DbContext' because of .net roles identity DB
public partial class ShareMemoriesContext : IdentityDbContext<ExtendIdentityUser> // : IdentityDbContext
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

        // Configure primary key for IdentityUserLogin
        modelBuilder.Entity<IdentityUserLogin<string>>()
            .HasKey(l => new { l.LoginProvider, l.ProviderKey, l.UserId });

        // Configure the primary key for IdentityUserRole
        modelBuilder.Entity<IdentityUserRole<string>>()
            .HasKey(ur => new { ur.UserId, ur.RoleId });

        //// creating relationships for Migrations\deployment
        //modelBuilder.Entity<Friendship>(entity =>
        //{
        //    entity.ToTable("Friendship");

        //    entity.Property(e => e.IsArchived).HasDefaultValue(false);

        //    //entity.HasOne(d => d.FriendsWith).WithMany(p => p.FriendshipFriendsWiths)
        //    //    .HasForeignKey(d => d.FriendsWithId)
        //    //    .OnDelete(DeleteBehavior.ClientSetNull)
        //    //    .HasConstraintName("FK_Friendship_User1");

        //    //entity.HasOne(d => d.User).WithMany(p => p.FriendshipUsers)
        //    //    .HasForeignKey(d => d.UserId)
        //    //    .OnDelete(DeleteBehavior.ClientSetNull)
        //    //    .HasConstraintName("FK_Friendship_User");
        //});

        modelBuilder.Entity<Picture>(entity =>
        {
            entity.ToTable("Picture");

            entity.Property(e => e.FriendlyName)
                .IsRequired()
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.IsArchived).HasDefaultValue(false);
            entity.Property(e => e.Picture1)
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
}