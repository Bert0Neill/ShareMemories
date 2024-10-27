using Microsoft.AspNetCore.Components;
using ShareMemories.Shared.DTOs;
using ShareMemories.Web.Interfaces;

namespace ShareMemories.Web.Pages.Registration
{
    public partial class Registration
    {
        private RegisterUserDto _userForRegistration = new();

        [Inject]
        public IAuthenticationService AuthenticationService { get; set; }
        [Inject]
        public NavigationManager NavigationManager { get; set; }
        public bool ShowRegistrationErrors { get; set; }
        public IEnumerable<string> Errors { get; set; }

        public async Task Register()
        {
            ShowRegistrationErrors = false;

            var result = await AuthenticationService.RegisterUser(_userForRegistration);
            if (!result.IsStatus)
            {
                //Errors = result.Message;
                Errors = new List<string> { result.Message };
                ShowRegistrationErrors = true;
            }
            else
            {
                NavigationManager.NavigateTo("/");
            }
        }
    }
}
