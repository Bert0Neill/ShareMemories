using Moq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using ShareMemories.Domain.Entities;
using ShareMemories.Application.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using ShareMemories.Infrastructure.Services;
using Microsoft.AspNetCore.Identity.UI.Services;
using ShareMemories.Domain.Models;

namespace ShareMemories.Tests
{
    [TestClass]
    public class AuthServiceTests
    {
        private Mock<UserManager<ExtendIdentityUser>> _userManagerMock;
        private Mock<SignInManager<ExtendIdentityUser>> _signInManagerMock;
        private Mock<RoleManager<IdentityRole>> _roleManagerMock;
        private Mock<IOptions<IdentityOptions>> _identityOptionsMock;
        private Mock<IConfiguration> _configMock;
        private Mock<IJwtTokenService> _jwtTokenServiceMock;
        private Mock<IHttpContextAccessor> _httpContextAccessorMock;
        private Mock<IEmailSender> _emailSenderMock;
        private Mock<IMemoryCache> _memoryCacheMock;
        private Mock<ILogger<AuthService>> _loggerMock;

        private AuthService _authService;

        [TestInitialize]
        public void Setup()
        {
            _configMock = new Mock<IConfiguration>();

            var jwtSectionMock = new Mock<IConfigurationSection>();
            jwtSectionMock.Setup(s => s["Key"]).Returns("6AD2EFDE-AB2C-4841-A05E-7045C855BA22");
            jwtSectionMock.Setup(s => s["Issuer"]).Returns("https://localhost:7273/");
            jwtSectionMock.Setup(s => s["Audience"]).Returns("https://localhost:7273/");
            jwtSectionMock.Setup(s => s["REFRESH_TOKEN_EXPIRE_DAYS"]).Returns("10");
            jwtSectionMock.Setup(s => s["JWT_TOKEN_EXPIRE_MINS"]).Returns("30");

            var systemDefaultsSectionMock = new Mock<IConfigurationSection>();
            systemDefaultsSectionMock.Setup(s => s["ProviderTokenLifeSpan"]).Returns("30");
            systemDefaultsSectionMock.Setup(s => s["LockoutLifeSpan"]).Returns("10");
            systemDefaultsSectionMock.Setup(s => s["LockoutAttempts"]).Returns("3");
            systemDefaultsSectionMock.Setup(s => s["Is2FAEnabled"]).Returns("False");
            systemDefaultsSectionMock.Setup(s => s["RememberMeLifeSpan"]).Returns("2");
            systemDefaultsSectionMock.Setup(s => s["AdminLocksAccountLifeSpan"]).Returns("7");

            _configMock.Setup(c => c.GetSection("Jwt")).Returns(jwtSectionMock.Object);
            _configMock.Setup(c => c.GetSection("SystemDefaults")).Returns(systemDefaultsSectionMock.Object);

            _jwtTokenServiceMock = new Mock<IJwtTokenService>();
            _jwtTokenServiceMock.Setup(j => j.GenerateJwtToken(It.IsAny<ExtendIdentityUser>(), It.IsAny<IList<string>>(), It.IsAny<int>()))
                .Returns("dummy-access-token");
            _jwtTokenServiceMock.Setup(j => j.GenerateRefreshToken())
                .Returns("dummy-refresh-token");

            _userManagerMock = new Mock<UserManager<ExtendIdentityUser>>(
                new Mock<IUserStore<ExtendIdentityUser>>().Object, null, null, null, null, null, null, null, null);
            _signInManagerMock = new Mock<SignInManager<ExtendIdentityUser>>(
                _userManagerMock.Object, new Mock<IHttpContextAccessor>().Object,
                new Mock<IUserClaimsPrincipalFactory<ExtendIdentityUser>>().Object, null, null, null, null);
            _roleManagerMock = new Mock<RoleManager<IdentityRole>>(
                new Mock<IRoleStore<IdentityRole>>().Object, null, null, null, null);
            _identityOptionsMock = new Mock<IOptions<IdentityOptions>>();
            _identityOptionsMock.Setup(i => i.Value).Returns(new IdentityOptions
            {
                SignIn = new SignInOptions { RequireConfirmedEmail = true },
                Lockout = new LockoutOptions { DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5) }
            });
            _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
            _emailSenderMock = new Mock<IEmailSender>();
            _memoryCacheMock = new Mock<IMemoryCache>();
            _loggerMock = new Mock<ILogger<AuthService>>();

            _authService = new AuthService(
                _loggerMock.Object, _memoryCacheMock.Object, _identityOptionsMock.Object,
                _roleManagerMock.Object, _userManagerMock.Object, _configMock.Object,
                _jwtTokenServiceMock.Object, _signInManagerMock.Object, _httpContextAccessorMock.Object,
                _emailSenderMock.Object);
        }

        [TestMethod]
        public async Task LoginAsync_ShouldReturnSuccess_WhenCredentialsAreValid()
        {
            // Mock UpdateAsync to return IdentityResult.Success (or other appropriate results)
            _userManagerMock.Setup(u => u.UpdateAsync(It.IsAny<ExtendIdentityUser>())).ReturnsAsync(IdentityResult.Success);

            // Mocking individual configuration sections and values
            _configMock.Setup(c => c["Jwt:JWT_TOKEN_EXPIRE_MINS"]).Returns("30");
            _configMock.Setup(c => c["Jwt:REFRESH_TOKEN_EXPIRE_DAYS"]).Returns("10");
            _configMock.Setup(c => c.GetSection("SystemDefaults:RememberMeLifeSpan").Value).Returns("30"); // Set remember me lifespan to 30 days

            // Mock the roles for the user
            var roles = new List<string> { "Admin", "User" };
            _userManagerMock.Setup(u => u.GetRolesAsync(It.IsAny<ExtendIdentityUser>())).ReturnsAsync(roles);

            // Arrange
            var loginModel = new LoginUserModel
            {
                UserName = "testuser",
                Password = "Password123!",
                IsPersistent = true
            };

            var user = new ExtendIdentityUser { UserName = "testuser" };

            _userManagerMock.Setup(u => u.FindByNameAsync(It.IsAny<string>())).ReturnsAsync(user);
            _userManagerMock.Setup(u => u.IsEmailConfirmedAsync(It.IsAny<ExtendIdentityUser>())).ReturnsAsync(true);
            _userManagerMock.Setup(u => u.IsLockedOutAsync(It.IsAny<ExtendIdentityUser>())).ReturnsAsync(false);

            _signInManagerMock.Setup(s => s.PasswordSignInAsync(It.IsAny<ExtendIdentityUser>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(SignInResult.Success);

            // Act
            var result = await _authService.LoginAsync(loginModel);

            // Assert
            Assert.IsTrue(result.IsStatus);
        }



        [TestMethod]
        public async Task LoginAsync_ShouldReturnFailure_WhenUserIsNotFound()
        {
            _signInManagerMock.Setup(s => s.PasswordSignInAsync(
               It.IsAny<string>(),
               It.IsAny<string>(),
               It.IsAny<bool>(),
               It.IsAny<bool>()
           )).ReturnsAsync(SignInResult.Failed); // Or other SignInResult depending on the test case


            // Arrange
            var loginModel = new LoginUserModel
            {
                UserName = "testuser",
                Password = "Password123!",
                IsPersistent = false
            };

            // Mock the configuration to return a specific value for the remember me lifespan
            _configMock.Setup(c => c.GetSection("SystemDefaults:RememberMeLifeSpan").Value)
                       .Returns("30"); // Set remember me lifespan to 30 days

            // Mock that the user is not found
            _userManagerMock.Setup(u => u.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync((ExtendIdentityUser)null); // User not found

            // Mock the password sign-in process to fail
            _signInManagerMock.Setup(s => s.PasswordSignInAsync(It.IsAny<ExtendIdentityUser>(), It.IsAny<string>(), false, true))
                .ReturnsAsync(SignInResult.Failed);

            // Act
            var result = await _authService.LoginAsync(loginModel);

            // Assert
            Assert.IsFalse(result.IsStatus);
            Assert.AreEqual("Credentials are not valid", result.Message);
        }
    }

    internal class JwtTokenPair
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}