using System.ComponentModel.DataAnnotations;

namespace AuthCenter.ViewModels
{
    public class RegisterUser
    {
        [Required]
        public string Name { get; set; } = String.Empty;
        [Required]
        public string Id { get; set; } = String.Empty;
        [Required]
        public string Password { get; set; } = String.Empty;
        [EmailAddress]
        public string? Email { get; set; }
        [Phone]
        public string? Phone { get; set; }
        public string EmailVerifyId { get; set; } = String.Empty;
        public string EmailVerifyCode { get; set; } = String.Empty;
        public string PhoneVerifyId { get; set; } = String.Empty;
        
        public string PhoneVerifyCode { get; set; } = String.Empty;
        public string GroupName { get; set; } = String.Empty;

        public string Code { get; set; } = String.Empty;        
        public string CaptchaId { get; set; } = String.Empty;
    }
}
