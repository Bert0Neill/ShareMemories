﻿// <auto-generated> This file has been auto generated by EF Core Power Tools. </auto-generated>
#nullable disable
using System;
using System.Collections.Generic;

namespace ShareMemories.Domain.Entities;

public partial class Picture
{
    public int Id { get; set; }

    public int UserId { get; set; }

    public string FriendlyName { get; set; }

    public byte[] Picture1 { get; set; }

    public bool? IsArchived { get; set; }

    public virtual User User { get; set; }
}