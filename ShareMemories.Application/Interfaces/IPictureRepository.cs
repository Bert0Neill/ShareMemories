using ShareMemories.Domain.Entities;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IPictureRepository
    {
        Task<Picture> InsertPictureAsync(Picture album);
        Task<IEnumerable<Picture>> RetrieveTopTenPicturesAsync();
        Task<Picture> UpdatePictureAsync(Picture album);
        Task<Picture> RetrievePictureByIdAsync(int id);
    }
}