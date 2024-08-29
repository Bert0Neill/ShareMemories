using ShareMemories.Domain.Entities;

namespace ShareMemories.Application.Interfaces
{
    public interface IVideoService
    {
        Task<Video> GetVideoByIdAsync(int id);
        List<Video> GetVideos();
        Task<Video> InsertVideoAsync(Video video);        
    }
}