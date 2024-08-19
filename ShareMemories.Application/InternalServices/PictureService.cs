using ShareMemories.Application.Interfaces;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.Application.InternalServices
{
    public class PictureService : IPictureService
    {
        private readonly List<Picture> _pictures = new();
        private readonly IPictureRepository _pictureRepository;

        public PictureService(IPictureRepository PictureRepository)
        {
            _pictureRepository = PictureRepository;

            // Create new Picture instances
            var picture1 = new Picture
            {
                Id = 1,
                UserId = 101,
                FriendlyName = "Sunset",
                PictureBytes = new byte[] { 0x01, 0x02, 0x03 }, // Example byte array
                IsArchived = false
            };

            var picture2 = new Picture
            {
                Id = 2,
                UserId = 102,
                FriendlyName = "Mountain",
                PictureBytes = new byte[] { 0x04, 0x05, 0x06 }, // Example byte array
                IsArchived = true
            };

            // Add Picture instances to the list
            _pictures.Add(picture1);
            _pictures.Add(picture2);

        }

        //public async Task<List<Picture>> GetPicturesAsync()
        //{
        //    return await _context.Pictures.ToListAsync();
        //}

        public List<Picture> GetPictures()
        {
            return this._pictures;
        }

        public async Task<Picture> GetPictureByIdAsync(int id)
        {
            var picture = await _pictureRepository.RetrievePictureByIdAsync(id);
            return picture;
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
