namespace AuthCenter.ViewModels
{
    public class TokenRequest
    {
        public required string grant_type { get; set; }
        public string code { get; set; }
        public string redirect_uri { get; set; }
    }
}
