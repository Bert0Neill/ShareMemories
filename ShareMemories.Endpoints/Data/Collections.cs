namespace ShareMemories.Endpoints.Data
{
    public static class Collections
    {
        public static List<User> Users = new()
        {
            new User()
            {
                Id = 1,
                FirstName = "Callie",
                LastName = "Hackforth",
                BirthDate = new DateOnly(1995, 10, 3)
            },
            new User()
            {
                Id = 2,
                FirstName = "Odell",
                LastName = "Blowes",
                BirthDate = new DateOnly(1984, 4, 7)
            },
            new User()
            {
                Id = 3,
                FirstName = "Callie",
                LastName = "Corrett",
                BirthDate = new DateOnly(1991, 3, 4)
            },
            new User()
            {
                Id = 4,
                FirstName = "Channa",
                LastName = "McKeggie",
                BirthDate = new DateOnly(1985, 11, 13)
            },
            new User()
            {
                Id = 5,
                FirstName = "Angelita",
                LastName = "Jubert",
                BirthDate = new DateOnly(1990, 1, 9)
            }
        };
    }
}
