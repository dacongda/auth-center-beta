using System.ComponentModel.DataAnnotations;

namespace AuthCenter.ViewModels.Request
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Password { get; set; } = "";
        [Required]
        public string ResetToken { get; set; } = "";
    }
}
