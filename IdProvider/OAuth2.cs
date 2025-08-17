using AuthCenter.Models;
using Newtonsoft.Json.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AuthCenter.IdProvider
{
    public class OAuth2(string clientId, string clientSecret, string tokenEndpoint, string userInfoEndpoint, string tokenType, string redirectUri, UserInfoMap userInfoMap) : IIdProvider
    {
        private readonly string _clientId = clientId;
        private readonly string _clientSecret = clientSecret;
        private readonly string _tokenType = tokenType;
        private readonly string _tokenEndpoint = tokenEndpoint;
        private readonly string _userInfoEndpoint = userInfoEndpoint;
        private readonly string _redirectUri = redirectUri;
        private readonly UserInfoMap _userInfoMap = userInfoMap;

        public class TokenResponse
        {
            public string AccessToken { get; set; } = string.Empty;
            public string RefreshToken { get; set; } = string.Empty;
            public string IdToken { get; set; } = string.Empty;
        }

        public async Task<UserInfo> getUserInfo(string code)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                client.DefaultRequestHeaders.Add("User-Agent", "Auth center");

                var requestParams = new Dictionary<string, string>
                {
                    {"grant_type", "authorization_code"},
                    {"code", code},
                    {"redirect_uri", _redirectUri},
                    {"client_id", _clientId},
                    {"client_secret", _clientSecret}
                };

                var request = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint)
                {
                    Content = new FormUrlEncodedContent(requestParams)
                };

                var response = await client.SendAsync(request);
                var responseContent = await response.Content.ReadAsStringAsync();
                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception($"获取令牌失败: {response.StatusCode} - {responseContent}");
                }

                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });
                if (tokenResponse is null)
                {
                    throw new Exception($"获取令牌失败: {response.StatusCode} - {responseContent}");
                }

                var infoRequest = new HttpRequestMessage(HttpMethod.Get, _userInfoEndpoint);
                infoRequest.Headers.Add("Authorization", $"{_tokenType} {tokenResponse.AccessToken}");

                var infoResponse = await client.SendAsync(infoRequest);
                var infoResponseContent = await infoResponse.Content.ReadAsStringAsync();
                
                var infoRoot = JObject.Parse(infoResponseContent);

                var id = infoRoot.SelectToken(_userInfoMap.Id);
                var name = infoRoot.SelectToken(_userInfoMap.Name);
                var preferredName = infoRoot.SelectToken(_userInfoMap.PreferredName);
                var email = infoRoot.SelectToken(_userInfoMap.Email ?? ".email");
                var phone = infoRoot.SelectToken(_userInfoMap.Phone == "" ? ".phone" : _userInfoMap.Phone);

                return new UserInfo
                {
                    Id = id?.Value<string>() ?? string.Empty,
                    Name = name?.Value<string>() ?? string.Empty,
                    PreferredName = preferredName?.Value<string>() ?? string.Empty,
                    Email = email?.Value<string>() ?? string.Empty,
                    Phone = phone?.Value<string>() ?? string.Empty,
                };
            }
        }
    }
}
