using ShareMemories.Application.Interfaces;
using ShareMemories.Domain.Entities;
using ShareMemories.Infrastructure.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Application.InternalServices
{
    

    public class VideoService : IVideoService
    {
        private readonly List<Video> _videos = new();
        private readonly IVideoRepository _videoRepository;

        public VideoService(IVideoRepository videoRepository)
        {
            _videoRepository = videoRepository;

            // Create new Video instances
            var video1 = new Video
            {
                Id = 1,
                UserId = 101,
                FriendlyName = "Sunset",
                VideoBytes = new byte[] { 0x01, 0x02, 0x03 }, // Example byte array
                IsArchived = false
            };

            var video2 = new Video
            {
                Id = 2,
                UserId = 102,
                FriendlyName = "Mountain",
                VideoBytes = new byte[] { 0x04, 0x05, 0x06 }, // Example byte array
                IsArchived = true
            };

            // Add Video instances to the list
            _videos.Add(video1);
            _videos.Add(video2);

        }

        //public async Task<List<Video>> GetVideosAsync()
        //{
        //    return await _context.Videos.ToListAsync();
        //}

        public List<Video> GetVideos()
        {
            return this._videos;
        }

        public async Task<Video> GetVideoByIdAsync(int id)
        {
            var Video = await _videoRepository.RetrieveVideoByIdAsync(id);
            return Video;
        }

        public Task<Video> InsertVideoAsync(Video video)
        {
            // use await for DB actions and remove FromResult below

            int maxId = _videos.Any() ? _videos.Max(x => x.Id) : 0;
            maxId++;
            video.Id = maxId;
            _videos.Add(video);

            return Task.FromResult(video);
        }
    }
}
