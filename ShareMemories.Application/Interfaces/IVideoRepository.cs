using ShareMemories.Domain.Entities;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IVideoRepository
    {
        Task<Video> InsertVideoAsync(Video album);
        Task<IEnumerable<Video>> RetrieveTopTenVideosAsync();
        Task<Video> UpdateVideoAsync(Video album);
        Task<Video> RetrieveVideoByIdAsync(int id);
    }
}