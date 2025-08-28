namespace AuthCenter.ViewModels.Request
{
    public class CaptchaRequest
    {
        public required int ProviderId { get; set; }
        public required string CaptchaCode { get; set; }
    }
}
