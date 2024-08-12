using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.Interfaces;
using System.Text.Json;

namespace ShareMemories.Infrastructure.ExternalServices.Database.Repositories
{
    public class PictureRepository : IPictureRepository
    {
        private readonly ShareMemoriesContext _musicDbContext;
        private readonly ILogger<PictureRepository> _logger;

        public PictureRepository(ShareMemoriesContext musicDbContext, ILogger<PictureRepository> logger)
        {
            _musicDbContext = musicDbContext;
            _logger = logger;

            _logger.LogInformation($"AlbumRepository ctor");
        }

        public async Task<IEnumerable<Picture>> RetrieveTopTenPicturesAsync()
        {
            _logger.LogInformation($"RetrieveTopTenAlbumsAsync");

            return await _musicDbContext.Pictures.Take(10).ToListAsync();
        }

        public async Task<Picture> RetrievePictureByIdAsync(int id)
        {
            _logger.LogInformation($"RetrievePictureByIdAsync - {JsonSerializer.Serialize(id)}");

            // Use FindAsync to asynchronously find the entity by its primary key
            var picture = await _musicDbContext.Pictures.FindAsync(id);

            if (picture == null)
            {
                _logger.LogWarning($"Picture with ID {id} not found.");
            }

            return picture;
        }


        public async Task<Picture> InsertPictureAsync(Picture album)
        {
            _logger.LogInformation($"InsertAlbumAsync - {JsonSerializer.Serialize(album)}");

            _musicDbContext.Pictures.Add(album);
            await _musicDbContext.SaveChangesAsync();

            return album;
        }

        public async Task<Picture> UpdatePictureAsync(Picture album)
        {
            _logger.LogInformation($"UpdateAlbumAsync - {JsonSerializer.Serialize(album)}");

            _musicDbContext.Update(album);
            await _musicDbContext.SaveChangesAsync();

            return album;
        }

    }
}
