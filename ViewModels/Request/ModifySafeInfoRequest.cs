using System.Runtime.CompilerServices;

namespace AuthCenter.ViewModels.Request
{
    public class ModifySafeInfoRequest
    {
        public string Type { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Phone { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string CodeId { get; set; } = string.Empty;
        public string VerifyCode { get; set;} = string.Empty;
    }
}
