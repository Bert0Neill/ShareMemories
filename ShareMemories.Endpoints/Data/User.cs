namespace ShareMemories.Endpoints.Data
{
    public class User
    {
        public int Id { get; init; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        internal DateOnly BirthDate { get; set; }
    }
}
