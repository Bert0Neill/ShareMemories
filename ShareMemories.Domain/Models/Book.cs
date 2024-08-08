using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Domain.Models
{
    public class Book
    {
        public int Id { get; set; }

        public required string Title { get; set; }

        public required string Author { get; set; }
    }
}
