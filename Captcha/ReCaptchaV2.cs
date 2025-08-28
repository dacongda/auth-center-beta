using Amazon.Runtime.Internal.Transform;
using Microsoft.AspNetCore.DataProtection;
using System.Text.Json;

namespace AuthCenter.Captcha
{
    public class ReCaptchaV2(string clientId, string clientSecret) : ICaptchaProvider
    {
        const string Endpoint = "https://recaptcha.net/recaptcha/api/siteverify";
        private readonly string _clientId = clientId;
        private readonly string _clientSecret = clientSecret;

        private readonly static JsonSerializerOptions _jsonSerializerOption = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };

        private class ReCaptchaResponse
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

                var reResponse = JsonSerializer.Deserialize<ReCaptchaResponse>(responseContent, _jsonSerializerOption);

                if (reResponse is null)
                {
                    return false;
                }

                return reResponse.Success;
            }
        }
    }
}
