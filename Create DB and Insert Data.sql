USE [master]
GO
/****** Object:  Database [ShareMemories]    Script Date: 02/08/2024 11:06:02 ******/
CREATE DATABASE [ShareMemories]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'ShareMemories', FILENAME = N'C:\Users\oneillb\ShareMemories.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'ShareMemories_log', FILENAME = N'C:\Users\oneillb\ShareMemories_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
GO
ALTER DATABASE [ShareMemories] SET COMPATIBILITY_LEVEL = 130
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [ShareMemories].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [ShareMemories] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [ShareMemories] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [ShareMemories] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [ShareMemories] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [ShareMemories] SET ARITHABORT OFF 
GO
ALTER DATABASE [ShareMemories] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [ShareMemories] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [ShareMemories] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [ShareMemories] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [ShareMemories] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [ShareMemories] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [ShareMemories] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [ShareMemories] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [ShareMemories] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [ShareMemories] SET  DISABLE_BROKER 
GO
ALTER DATABASE [ShareMemories] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [ShareMemories] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [ShareMemories] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [ShareMemories] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [ShareMemories] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [ShareMemories] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [ShareMemories] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [ShareMemories] SET RECOVERY SIMPLE 
GO
ALTER DATABASE [ShareMemories] SET  MULTI_USER 
GO
ALTER DATABASE [ShareMemories] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [ShareMemories] SET DB_CHAINING OFF 
GO
ALTER DATABASE [ShareMemories] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [ShareMemories] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [ShareMemories] SET DELAYED_DURABILITY = DISABLED 
GO
ALTER DATABASE [ShareMemories] SET QUERY_STORE = OFF
GO
USE [ShareMemories]
GO
ALTER DATABASE SCOPED CONFIGURATION SET LEGACY_CARDINALITY_ESTIMATION = OFF;
GO
ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 0;
GO
ALTER DATABASE SCOPED CONFIGURATION SET PARAMETER_SNIFFING = ON;
GO
ALTER DATABASE SCOPED CONFIGURATION SET QUERY_OPTIMIZER_HOTFIXES = OFF;
GO
USE [ShareMemories]
GO
/****** Object:  Table [dbo].[Friendship]    Script Date: 02/08/2024 11:06:02 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Friendship](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[UserId] [int] NOT NULL,
	[FriendsWithId] [int] NOT NULL,
	[IsArchived] [bit] NULL,
 CONSTRAINT [PK_Friendship] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Picture]    Script Date: 02/08/2024 11:06:02 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Picture](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[UserId] [int] NOT NULL,
	[FriendlyName] [varchar](100) NOT NULL,
	[Picture] [varbinary](max) NOT NULL,
	[IsArchived] [bit] NULL,
 CONSTRAINT [PK_Picture] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[User]    Script Date: 02/08/2024 11:06:02 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[User](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Username] [varchar](100) NOT NULL,
	[Firstname] [varchar](100) NOT NULL,
	[Lastname] [varchar](100) NOT NULL,
	[Email] [varchar](100) NOT NULL,
	[Password] [varchar](100) NOT NULL,
	[LastUpdated] [datetime] NULL,
	[CreatedDate] [datetime] NULL,
	[IsArchived] [bit] NULL,
 CONSTRAINT [PK_User] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Video]    Script Date: 02/08/2024 11:06:02 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Video](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[UserId] [int] NOT NULL,
	[FriendlyName] [varchar](100) NOT NULL,
	[URL] [varchar](100) NOT NULL,
	[IsWatched] [bit] NULL,
	[IsArchived] [bit] NULL,
 CONSTRAINT [PK_Video] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[Friendship] ON 
GO
INSERT [dbo].[Friendship] ([Id], [UserId], [FriendsWithId], [IsArchived]) VALUES (1, 1, 2, 0)
GO
INSERT [dbo].[Friendship] ([Id], [UserId], [FriendsWithId], [IsArchived]) VALUES (2, 2, 1, 0)
GO
INSERT [dbo].[Friendship] ([Id], [UserId], [FriendsWithId], [IsArchived]) VALUES (3, 3, 4, 0)
GO
INSERT [dbo].[Friendship] ([Id], [UserId], [FriendsWithId], [IsArchived]) VALUES (4, 4, 3, 0)
GO
SET IDENTITY_INSERT [dbo].[Friendship] OFF
GO
SET IDENTITY_INSERT [dbo].[Picture] ON 
GO
INSERT [dbo].[Picture] ([Id], [UserId], [FriendlyName], [Picture], [IsArchived]) VALUES (1, 1, N'My picture 1', 0x696D6167655F646174615F31, 0)
GO
INSERT [dbo].[Picture] ([Id], [UserId], [FriendlyName], [Picture], [IsArchived]) VALUES (2, 2, N'My picture 2', 0x696D6167655F646174615F32, 0)
GO
INSERT [dbo].[Picture] ([Id], [UserId], [FriendlyName], [Picture], [IsArchived]) VALUES (3, 3, N'My picture 3', 0x696D6167655F646174615F33, 0)
GO
INSERT [dbo].[Picture] ([Id], [UserId], [FriendlyName], [Picture], [IsArchived]) VALUES (4, 4, N'My picture 4', 0x696D6167655F646174615F34, 0)
GO
SET IDENTITY_INSERT [dbo].[Picture] OFF
GO
SET IDENTITY_INSERT [dbo].[User] ON 
GO
INSERT [dbo].[User] ([Id], [Username], [Firstname], [Lastname], [Email], [Password], [LastUpdated], [CreatedDate], [IsArchived]) VALUES (1, N'john_doe', N'John', N'Doe', N'john.doe@example.com', N'hashed_password_123', CAST(N'2024-08-02T11:04:41.887' AS DateTime), CAST(N'2024-08-02T11:04:41.887' AS DateTime), 0)
GO
INSERT [dbo].[User] ([Id], [Username], [Firstname], [Lastname], [Email], [Password], [LastUpdated], [CreatedDate], [IsArchived]) VALUES (2, N'jane_smith', N'Jane', N'Smith', N'jane.smith@example.com', N'hashed_password_456', CAST(N'2024-08-02T11:04:41.887' AS DateTime), CAST(N'2024-08-02T11:04:41.887' AS DateTime), 0)
GO
INSERT [dbo].[User] ([Id], [Username], [Firstname], [Lastname], [Email], [Password], [LastUpdated], [CreatedDate], [IsArchived]) VALUES (3, N'alice_jones', N'Alice', N'Jones', N'alice.jones@example.com', N'hashed_password_789', CAST(N'2024-08-02T11:04:41.887' AS DateTime), CAST(N'2024-08-02T11:04:41.877' AS DateTime), 0)
GO
INSERT [dbo].[User] ([Id], [Username], [Firstname], [Lastname], [Email], [Password], [LastUpdated], [CreatedDate], [IsArchived]) VALUES (4, N'bob_brown', N'Bob', N'Brown', N'bob.brown@example.com', N'hashed_password_012', CAST(N'2024-08-02T11:04:41.887' AS DateTime), CAST(N'2024-08-02T11:04:41.877' AS DateTime), 0)
GO
SET IDENTITY_INSERT [dbo].[User] OFF
GO
SET IDENTITY_INSERT [dbo].[Video] ON 
GO
INSERT [dbo].[Video] ([Id], [UserId], [FriendlyName], [URL], [IsWatched], [IsArchived]) VALUES (1, 1, N'My video 1', N'https://www.youtube.com/watch?v=-wtIMTCHWuI', 0, 0)
GO
INSERT [dbo].[Video] ([Id], [UserId], [FriendlyName], [URL], [IsWatched], [IsArchived]) VALUES (2, 2, N'My video 4', N'http://youtube.com/watch?v=-wtIMTCHWuI', 1, 0)
GO
INSERT [dbo].[Video] ([Id], [UserId], [FriendlyName], [URL], [IsWatched], [IsArchived]) VALUES (3, 3, N'My video 3', N'http://m.youtube.com/watch?v=-wtIMTCHWuI', 0, 0)
GO
INSERT [dbo].[Video] ([Id], [UserId], [FriendlyName], [URL], [IsWatched], [IsArchived]) VALUES (4, 4, N'My video 5', N'https://www.youtube.com/watch?v=lalOy8Mbfdc', 1, 0)
GO
SET IDENTITY_INSERT [dbo].[Video] OFF
GO
ALTER TABLE [dbo].[Friendship] ADD  CONSTRAINT [DF_Friendship_IsArchived]  DEFAULT ((0)) FOR [IsArchived]
GO
ALTER TABLE [dbo].[Picture] ADD  CONSTRAINT [DF_Picture_IsArchived]  DEFAULT ((0)) FOR [IsArchived]
GO
ALTER TABLE [dbo].[User] ADD  CONSTRAINT [DF_User_IsArchived]  DEFAULT ((0)) FOR [IsArchived]
GO
ALTER TABLE [dbo].[Video] ADD  CONSTRAINT [DF_Video_IsWatched]  DEFAULT ((0)) FOR [IsWatched]
GO
ALTER TABLE [dbo].[Video] ADD  CONSTRAINT [DF_Video_IsArchived]  DEFAULT ((0)) FOR [IsArchived]
GO
ALTER TABLE [dbo].[Friendship]  WITH CHECK ADD  CONSTRAINT [FK_Friendship_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Friendship] CHECK CONSTRAINT [FK_Friendship_User]
GO
ALTER TABLE [dbo].[Friendship]  WITH CHECK ADD  CONSTRAINT [FK_Friendship_User1] FOREIGN KEY([FriendsWithId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Friendship] CHECK CONSTRAINT [FK_Friendship_User1]
GO
ALTER TABLE [dbo].[Picture]  WITH CHECK ADD  CONSTRAINT [FK_Picture_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Picture] CHECK CONSTRAINT [FK_Picture_User]
GO
ALTER TABLE [dbo].[Video]  WITH CHECK ADD  CONSTRAINT [FK_Video_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Video] CHECK CONSTRAINT [FK_Video_User]
GO
USE [master]
GO
ALTER DATABASE [ShareMemories] SET  READ_WRITE 
GO
