using ShareMemories.Domain.Entities;

namespace ShareMemories.Application.Interfaces
{
    public interface IPictureService
    {
        Task<Picture> GetPictureByIdAsync(int id);
        List<Picture> GetPictures();
        Task<Picture> InsertPictureAsync(Picture picture);        
    }
}