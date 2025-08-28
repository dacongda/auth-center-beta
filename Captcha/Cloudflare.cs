using System.Text.Json;

namespace AuthCenter.Captcha
{
    public class Cloudflare(string clientId, string clientSecret) : ICaptchaProvider
    {
        const string Endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
        private readonly string _clientId = clientId;
        private readonly string _clientSecret = clientSecret;

        private readonly static JsonSerializerOptions _jsonSerializerOption = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };

        private class CfCaptchaResponse
        {
            public bool Success { get; set; }
            public DateTime ChallengeTs { get; set; }
        }

        public bool VerifyCode(string captchaId, string code, string userIp)
        {
            using (var client = new HttpClient())
            {
                var requestParams = new Dictionary<string, string>
                {
                    {"secret", _clientSecret},
                    {"response", code}
                };

                var request = new HttpRequestMessage(HttpMethod.Post, Endpoint)
                {
                    Content = new FormUrlEncodedContent(requestParams)
                };

                var response = client.Send(request);
                var responseContent = response.Content.ReadAsStream();

                var cfResponse = JsonSerializer.Deserialize<CfCaptchaResponse>(responseContent, _jsonSerializerOption);

                if (cfResponse is null)
                {
                    return false;
                }

                return cfResponse.Success;
            }
        }
    }
}
