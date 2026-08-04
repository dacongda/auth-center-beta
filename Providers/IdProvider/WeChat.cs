using AuthCenter.Models;
using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json.Linq;

namespace AuthCenter.Providers.IdProvider
{
    public class WeChat(
        string appId,
        string appSecret,
        string tokenEndpoint,
        string userInfoEndpoint,
        UserInfoMap? userInfoMap,
        IDistributedCache cache) : IIdProvider
    {
        public const string DefaultAuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect";
        public const string DefaultTokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";
        public const string DefaultUserInfoEndpoint = "https://api.weixin.qq.com/sns/userinfo";

        private readonly string _appId = appId;
        private readonly string _appSecret = appSecret;
        private readonly string _tokenEndpoint = string.IsNullOrWhiteSpace(tokenEndpoint)
            ? DefaultTokenEndpoint
            : tokenEndpoint;
        private readonly string _userInfoEndpoint = string.IsNullOrWhiteSpace(userInfoEndpoint)
            ? DefaultUserInfoEndpoint
            : userInfoEndpoint;
        private readonly UserInfoMap _userInfoMap = userInfoMap ?? new UserInfoMap();
        private readonly IDistributedCache _cache = cache;

        public async Task<UserInfo> getUserInfo(string code, string? state, string? tempId)
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                throw new Exception("微信授权码不能为空");
            }

            await ValidateState(tempId, state);

            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.DefaultRequestHeaders.Add("User-Agent", "Auth center");

            var tokenUrl = BuildUrl(_tokenEndpoint, new Dictionary<string, string>
            {
                ["appid"] = _appId,
                ["secret"] = _appSecret,
                ["code"] = code,
                ["grant_type"] = "authorization_code"
            });
            var tokenRoot = await GetJson(client, tokenUrl, "获取微信令牌失败");

            var accessToken = tokenRoot.Value<string>("access_token");
            var openId = tokenRoot.Value<string>("openid");
            if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(openId))
            {
                throw new Exception("获取微信令牌失败: 响应缺少 access_token 或 openid");
            }

            var userInfoUrl = BuildUrl(_userInfoEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = accessToken,
                ["openid"] = openId,
                ["lang"] = "zh_CN"
            });
            var infoRoot = await GetJson(client, userInfoUrl, "获取微信用户信息失败");

            var id = SelectString(infoRoot, _userInfoMap.Id);
            if (string.IsNullOrWhiteSpace(id))
            {
                id = infoRoot.Value<string>("unionid");
            }
            if (string.IsNullOrWhiteSpace(id))
            {
                id = infoRoot.Value<string>("openid");
            }
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new Exception("获取微信用户信息失败: 响应缺少用户标识");
            }

            var nickname = infoRoot.Value<string>("nickname") ?? string.Empty;
            return new UserInfo
            {
                Id = id,
                Name = SelectString(infoRoot, _userInfoMap.Name) ?? nickname,
                PreferredName = SelectString(infoRoot, _userInfoMap.PreferredName) ?? nickname,
                Email = SelectString(infoRoot, _userInfoMap.Email) ?? string.Empty,
                Phone = SelectString(infoRoot, _userInfoMap.Phone) ?? string.Empty
            };
        }

        private async Task ValidateState(string? tempId, string? state)
        {
            if (string.IsNullOrWhiteSpace(tempId))
            {
                throw new Exception("tempId required");
            }

            var cacheKey = $"Bind:OAuth:{tempId}";
            var challengeState = await _cache.GetStringAsync(cacheKey);
            if (challengeState is null)
            {
                throw new Exception("error tempId");
            }

            await _cache.RemoveAsync(cacheKey);
            var parsedChallengeState = challengeState.Split(',', 2);
            if (parsedChallengeState.Length != 2 || state != parsedChallengeState[1])
            {
                throw new Exception("state check failed");
            }
        }

        private static async Task<JObject> GetJson(HttpClient client, string url, string errorMessage)
        {
            var response = await client.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();

            JObject root;
            try
            {
                root = JObject.Parse(content);
            }
            catch
            {
                throw new Exception($"{errorMessage}: {response.StatusCode} - 无效的响应");
            }

            var errorCode = root.Value<int?>("errcode");
            if (!response.IsSuccessStatusCode || (errorCode.HasValue && errorCode.Value != 0))
            {
                var providerMessage = root.Value<string>("errmsg");
                throw new Exception(
                    $"{errorMessage}: {errorCode?.ToString() ?? response.StatusCode.ToString()} - {providerMessage ?? content}");
            }

            return root;
        }

        private static string BuildUrl(string endpoint, Dictionary<string, string> query)
        {
            var builder = new UriBuilder(endpoint);
            var existingQuery = builder.Query.TrimStart('?');
            var encodedQuery = new FormUrlEncodedContent(query).ReadAsStringAsync().GetAwaiter().GetResult();
            builder.Query = string.IsNullOrEmpty(existingQuery)
                ? encodedQuery
                : $"{existingQuery}&{encodedQuery}";
            return builder.Uri.ToString();
        }

        private static string? SelectString(JObject root, string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            return root.SelectToken(path)?.Value<string>();
        }
    }
}

