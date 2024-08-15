using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace ShareMemories.Infrastructure.ExternalServices.Email
{
    public class EmailService : IEmailSender
    {

        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;
        private readonly ISendGridClient _sendGridClient;


        public EmailService(IConfiguration configuration, ILogger<EmailService> logger, ISendGridClient sendGridClient)
        {
            _configuration = configuration;
            _logger = logger;
            _sendGridClient = sendGridClient;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            var msg = new SendGridMessage()
            {
                From = new EmailAddress(_configuration["From"], _configuration["Name"]),
                Subject = subject,
                PlainTextContent = message,
                HtmlContent = message
            };
            msg.AddTo(new EmailAddress(toEmail));

            var response = await _sendGridClient.SendEmailAsync(msg);
            _logger.LogInformation(response.IsSuccessStatusCode
                                   ? $"Email to {toEmail} queued successfully!"
                                   : $"Failure Email to {toEmail}");
        }
        //private readonly ILogger _logger;
        //private readonly IConfiguration _configuration;

        //public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        //{
        //    _configuration = configuration;
        //    _logger = logger;
        //}

        //public async Task SendEmailAsync(string toEmail, string subject, string message)
        //{
        //    var sendGridKey = _configuration["SendGridKey"];
        //    ArgumentNullException.ThrowIfNullOrEmpty(sendGridKey, nameof(sendGridKey));
        //    await Execute(sendGridKey, subject, message, toEmail);
        //}

        //public async Task Execute(string apiKey, string subject, string message, string toEmail)
        //{
        //    var client = new SendGridClient(apiKey);

        //    var msg = new SendGridMessage()
        //    {
        //        From = new EmailAddress(_configuration["From"], _configuration["Name"]),
        //        Subject = subject,
        //        PlainTextContent = message,
        //        HtmlContent = message
        //    };

        //    msg.AddTo(new EmailAddress(toEmail));

        //    // Disable click tracking.
        //    // See https://sendgrid.com/docs/User_Guide/Settings/tracking.html
        //    msg.SetClickTracking(false, false);

        //    var response = await client.SendEmailAsync(msg);
        //    _logger.LogInformation(response.IsSuccessStatusCode
        //                           ? $"Email to {toEmail} queued successfully!"
        //                           : $"Failure Email to {toEmail}");
        //}
    }
}
