﻿// <auto-generated> This file has been auto generated by EF Core Power Tools. </auto-generated>
#nullable disable
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace ShareMemories.Domain.Entities;

public partial class Video
{
    [Key]
    public int Id { get; set; }

    public int UserId { get; set; }

    public string FriendlyName { get; set; }

    public string Url { get; set; }

    public bool? IsWatched { get; set; }

    public bool? IsArchived { get; set; }
    public byte[] VideoBytes { get; set; }

}