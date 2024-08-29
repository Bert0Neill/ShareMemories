using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Database;
using ShareMemories.Infrastructure.Interfaces;
using System.Text.Json;

namespace ShareMemories.Infrastructure.ExternalServices.Database.Repositories
{
    public class VideoRepository : IVideoRepository
    {
        private readonly ShareMemoriesContext _musicDbContext;
        private readonly ILogger<VideoRepository> _logger;

        public VideoRepository(ShareMemoriesContext musicDbContext, ILogger<VideoRepository> logger)
        {
            _musicDbContext = musicDbContext;
            _logger = logger;

            _logger.LogInformation($"VideoRepository ctor");
        }

        public async Task<IEnumerable<Video>> RetrieveTopTenVideosAsync()
        {
            _logger.LogInformation($"RetrieveTopTenVideosAsync");

            return await _musicDbContext.Videos.Take(10).ToListAsync();
        }

        public async Task<Video> RetrieveVideoByIdAsync(int id)
        {
            _logger.LogInformation($"RetrieveVideoByIdAsync - {JsonSerializer.Serialize(id)}");

            // Use FindAsync to asynchronously find the entity by its primary key
            var video = await _musicDbContext.Videos.FindAsync(id);

            if (video == null)
            {
                _logger.LogWarning($"Video with ID {id} not found.");
            }

            return video;
        }


        public async Task<Video> InsertVideoAsync(Video video)
        {
            _logger.LogInformation($"InsertVideoAsync - {JsonSerializer.Serialize(video)}");

            _musicDbContext.Videos.Add(video);
            await _musicDbContext.SaveChangesAsync();

            return video;
        }

        public async Task<Video> UpdateVideoAsync(Video video)
        {
            _logger.LogInformation($"UpdateVideoAsync - {JsonSerializer.Serialize(video)}");

            _musicDbContext.Update(video);
            await _musicDbContext.SaveChangesAsync();

            return video;
        }

    }
}
