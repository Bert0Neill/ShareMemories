using ShareMemories.Domain.Entities;

namespace ShareMemories.Application.Interfaces
{
    public interface IPictureService
    {
        Picture GetPicture(int id);
        List<Picture> GetPictures();
    }
}