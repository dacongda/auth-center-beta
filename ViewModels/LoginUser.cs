using System.ComponentModel.DataAnnotations;

namespace AuthCenter.ViewModels
{
    public class LoginUser
    {
        public required string Name { get; set; }
        public required string Password { get; set; }
        public string? Type { get; set; }
        public string? ChaptchaId { get; set; }
    }
    public class LoginResult
    {
        public string? AccessToken { get; set; }
    }
}
