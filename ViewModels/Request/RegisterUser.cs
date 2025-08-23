using System.ComponentModel.DataAnnotations;

namespace AuthCenter.ViewModels.Request
{
    public class RegisterUser
    {
        [Required]
        public string Name { get; set; } = string.Empty;
        [Required]
        public string Id { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
        [EmailAddress]
        public string? Email { get; set; }
        [Phone]
        public string? Phone { get; set; }
        public string EmailVerifyId { get; set; } = string.Empty;
        public string EmailVerifyCode { get; set; } = string.Empty;
        public string PhoneVerifyId { get; set; } = string.Empty;
        
        public string PhoneVerifyCode { get; set; } = string.Empty;
        public string GroupName { get; set; } = string.Empty;

        public string Code { get; set; } = string.Empty;        
        public string CaptchaId { get; set; } = string.Empty;
    }
}
