-- Insert mock data into [dbo].[Friendship] table
-- Use the User IDs inserted above
INSERT INTO [dbo].[Friendships] (UserId, FriendsWithId, IsArchived)
VALUES
(1, 2, 0), -- John Doe is friends with Jane Smith
(2, 1, 0), -- Jane Smith is friends with John Doe (bi-directional friendship)
(3, 4, 0), -- Alice Jones is friends with Bob Brown
(4, 3, 0); -- Bob Brown is friends with Alice Jones (bi-directional friendship)

-- Insert mock data into [dbo].[Picture] table
-- Use the User IDs inserted above
-- For simplicity, we'll use dummy binary data for the pictures
INSERT INTO [dbo].[Picture] (UserId, FriendlyName, Picture, IsArchived)
VALUES
(1, 'My picture 1', CAST('image_data_1' AS VARBINARY(MAX)), 0), -- Picture for John Doe
(2, 'My picture 2',CAST('image_data_2' AS VARBINARY(MAX)), 0), -- Picture for Jane Smith
(3, 'My picture 3',CAST('image_data_3' AS VARBINARY(MAX)), 0), -- Picture for Alice Jones
(4, 'My picture 4',CAST('image_data_4' AS VARBINARY(MAX)), 0); -- Picture for Bob Brown

-- Insert mock data into [dbo].[Video] table
-- Use the User IDs inserted above
INSERT INTO [dbo].[Video] (UserId, FriendlyName, URL, IsWatched, IsArchived)
VALUES
(1, 'My video 1', 'https://www.youtube.com/watch?v=-wtIMTCHWuI', 0, 0), -- Video for John Doe
(2, 'My video 4', 'http://youtube.com/watch?v=-wtIMTCHWuI', 1, 0), -- Video for Jane Smith
(3, 'My video 3', 'http://m.youtube.com/watch?v=-wtIMTCHWuI', 0, 0), -- Video for Alice Jones
(4, 'My video 5', 'https://www.youtube.com/watch?v=lalOy8Mbfdc', 1, 0); -- Video for Bob Brown
