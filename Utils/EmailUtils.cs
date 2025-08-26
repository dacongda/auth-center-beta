using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
namespace AuthCenter.Utils
{
    public class EmailUtils
    {
        public static bool SendEmail(string smtpServer, int port, bool enableSSL, string username, string password, string destination, string subject, string body)
        {
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse(username));
            message.To.Add(MailboxAddress.Parse(destination));
            message.Subject = subject;

            var builder = new BodyBuilder();
            builder.HtmlBody = body;

            message.Body = builder.ToMessageBody();


            using (var client = new SmtpClient())
            {
                client.Connect(smtpServer, port, SecureSocketOptions.Auto);
                client.Authenticate(username, password);
                client.Send(message);
                client.Disconnect(true);
            }
            return true;
        }
    }
}
