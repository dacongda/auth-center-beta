using AuthCenter.Models;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using Mono.TextTemplating;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace AuthCenter.Providers.IdProvider
{
    public class OIDC(string clientId, string clientSecret, bool useUserEndpoint,
        string tokenEndpoint, string userInfoEndpoint, string jwksEndpoint, string jwks,
        string tokenType, string redirectUri, UserInfoMap userInfoMap, IDistributedCache cache) : IIdProvider
    {
        private readonly string _clientId = clientId;
        private readonly string _clientSecret = clientSecret;
        private readonly string _tokenType = tokenType;
        private readonly string _tokenEndpoint = tokenEndpoint;
        private readonly string _jwksEndpoint = jwksEndpoint;
        private readonly string _jwks = jwks;
        private readonly string _userInfoEndpoint = userInfoEndpoint;
        private readonly bool _useUserEndpoint = useUserEndpoint;
        private readonly string _redirectUri = redirectUri;
        private readonly UserInfoMap _userInfoMap = userInfoMap;
        private readonly IDistributedCache _cache = cache;

        public class TokenResponse
        {
            public string AccessToken { get; set; } = string.Empty;
            public string RefreshToken { get; set; } = string.Empty;
            public string IdToken { get; set; } = string.Empty;
        }

        public async Task<UserInfo> getUserInfo(string code, string? state, string? tempId)
        {
            if (_tokenType == "id_token")
            {
                return await GetUserInfoByIdToken(code);
            }
            else
            {
                return await GetUserInfoByCode(code, state, tempId);
            }
        }

        private async Task<UserInfo> GetUserInfoByIdToken(string idToken)
        {
            string jwkString = _jwks;
            if (_jwks == "")
            {
                using var client = new HttpClient();
                var request = new HttpRequestMessage(HttpMethod.Get, _jwksEndpoint);
                var result = await client.SendAsync(request);
                jwkString = await result.Content.ReadAsStringAsync();

            }

            var jwkObjs = JsonWebKeySet.Create(_jwks);
            var tokenObj = new JwtSecurityToken(idToken);

            var tokenKid = tokenObj.Header.Kid;

            var jwk = jwkObjs.Keys.FirstOrDefault(k => k.Kid == tokenKid);
            if (jwk == null)
            {
                throw new Exception("未找到符合id_token的证书");
            }

            var validateParameter = new TokenValidationParameters()
            {
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _redirectUri,
                ValidAudience = _clientId,
                IssuerSigningKey = jwk,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                var claims = (await new JwtSecurityTokenHandler().ValidateTokenAsync(idToken, validateParameter)).Claims;

                var infoRoot = JObject.FromObject(claims);
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
            catch (Exception)
            {
                throw new Exception("id_token 校验错误");
            }
        }

        private async Task<UserInfo> GetUserInfoByCode(string code, string? state, string? tempId)
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

                if (String.IsNullOrEmpty(tempId))
                {
                    throw new Exception("tempId required");
                }

                var challengeState = await _cache.GetStringAsync($"Bind:OAuth:{tempId}");
                if (challengeState == null)
                {
                    throw new Exception("error tempId");
                }
                _ = _cache.RemoveAsync($"Bind:OAuth:{tempId}");
                var parsedChallengeState = challengeState.Split(",");
                requestParams.Add("code_verifier", parsedChallengeState[0]);

                if (state != parsedChallengeState[1])
                {
                    throw new Exception("state check failed");
                }

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

                if (!_useUserEndpoint)
                {
                    return await GetUserInfoByIdToken(tokenResponse.IdToken);
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
