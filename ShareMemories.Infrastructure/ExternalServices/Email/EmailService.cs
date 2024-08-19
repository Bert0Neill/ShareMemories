using Mailosaur;
using Mailosaur.Models;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using ShareMemories.Infrastructure.Interfaces;

namespace ShareMemories.Infrastructure.ExternalServices.Email
{
    public class EmailService : IEmailSender, IEmailService
    {

        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;
        private readonly MailosaurClient _mailosaurClient;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger, MailosaurClient mailosaurClient)
        {
            _configuration = configuration;
            _logger = logger;
            _mailosaurClient = mailosaurClient;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            var response = _mailosaurClient.Messages.Create(_configuration["Mailosaur:ServerId"], new MessageCreateOptions()
            {
                From = _configuration["Mailosaur:From"], // a valid Mailosaur email account
                To = toEmail,
                Send = true,
                Subject = subject,
                Text = message
            });

            _logger.LogInformation($"{toEmail} was emailed at {response.Received}");
        }
    }
}
