

using ShareMemories.Domain.Models;

namespace ShareMemories.Infrastructure.Interfaces
{
    public interface IBookService
    {
        List<Book> GetBooks();
        Book GetBook(int id);
        void ThrowException();
    }
}
