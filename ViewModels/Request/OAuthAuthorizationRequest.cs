namespace AuthCenter.ViewModels.Request
{
    public class OAuthAuthorizationRequest
    {
        public string[]? scope { get; set; }
        public string? response_type { get; set; }
        public required string client_id { get; set; }
        public required string redirect_uri { get; set; }
        public string? state { get; set; }
        public string? nonce { get; set; }
    }
}
