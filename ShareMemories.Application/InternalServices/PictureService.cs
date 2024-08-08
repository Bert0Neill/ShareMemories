using ShareMemories.Application.Interfaces;
using ShareMemories.Domain.Entities;
using ShareMemories.Domain.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Application.InternalServices
{
    public class PictureService : IPictureService
    {
        private readonly List<Picture> _pictures = new();
        public PictureService()
        {

            // Create new Picture instances
            var picture1 = new Picture
            {
                Id = 1,
                UserId = 101,
                FriendlyName = "Sunset",
                Picture1 = new byte[] { 0x01, 0x02, 0x03 }, // Example byte array
                IsArchived = false,
                User = new User { Id = 101, Username = "John Doe" } // Assuming User class exists
            };

            var picture2 = new Picture
            {
                Id = 2,
                UserId = 102,
                FriendlyName = "Mountain",
                Picture1 = new byte[] { 0x04, 0x05, 0x06 }, // Example byte array
                IsArchived = true,
                User = new User { Id = 102, Username = "Jane Smith" } // Assuming User class exists
            };

            // Add Picture instances to the list
            _pictures.Add(picture1);
            _pictures.Add(picture2);

        }

        public List<Picture> GetPictures()
        {
            return this._pictures;
        }

        public Task<Picture> GetPictureAsync(int id)
        {
            // use await for DB actions and remove FromResult below

            var picture = _pictures.Find(x => x.Id == id);
            return Task.FromResult(picture);
        }

        public Task<Picture> InsertPictureAsync(Picture picture)
        {
            // use await for DB actions and remove FromResult below

            int maxId = _pictures.Any() ? _pictures.Max(x => x.Id) : 0;
            maxId++;
            picture.Id = maxId;
            _pictures.Add(picture);

            return Task.FromResult(picture);
        }
    }
}
