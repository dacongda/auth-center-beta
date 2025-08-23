namespace AuthCenter.ViewModels.Request
{
    public class VerificationCodeRequest
    {
        public string Destination { get; set; } = "";
        public int? ApplicationId { get; set; }
        public string AuthType { get; set; } = "";
        public string VerifyId { get; set; } = "";
        public string CaptchaId { get; set; } = "";
        public string CaptchaCode { get; set; } = "";
    }
}
