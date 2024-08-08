using ShareMemories.Domain.Entities;

namespace ShareMemories.Application.Interfaces
{
    public interface IPictureService
    {
        Task<Picture> GetPictureAsync(int id);
        List<Picture> GetPictures();
        Task<Picture> InsertPictureAsync(Picture picture);
    }
}