using System.Text.Json;

namespace AuthCenter.Captcha
{
    public class HCaptcha(string clientId, string clientSecret) : ICaptchaProvider
    {
        const string Endpoint = "https://api.hcaptcha.com/siteverify";
        private readonly string _clientId = clientId;
        private readonly string _clientSecret = clientSecret;

        private readonly static JsonSerializerOptions _jsonSerializerOption = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };

        private class HCaptchaResponse
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

                var hResponse = JsonSerializer.Deserialize<HCaptchaResponse>(responseContent, _jsonSerializerOption);

                if (hResponse is null)
                {
                    return false;
                }

                return hResponse.Success;
            }
        }
    }
}
