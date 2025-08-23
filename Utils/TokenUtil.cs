using AuthCenter.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthCenter.Utils
{
    public class TokenUtil
    {
        public class JwtTokenPack
        {
            public string? IdToken;
            public string? AccessToken;
            public string? RefreshToken;
        }

        public static JwtTokenPack GenerateCodeToken(string tokenId, Cert cert, User user, Application application, string url, string scopes, string? nonce)
        {
            var scopeList = scopes.Split(' ');
            var allowedScope = application.Scopes?.Intersect(scopeList).ToArray() ?? [];

            var certKey = cert.ToSecurityKey();
            var signingCredentials = new SigningCredentials(certKey, $"{cert.CryptoAlgorithm}{cert.CryptoSHASize}");

            return new JwtTokenPack
            {
                IdToken = GenerateIdToken($"{tokenId}-id_token", user, application, signingCredentials, allowedScope, url, nonce),
                AccessToken = GenerateToken($"{tokenId}-access_token", user, application, signingCredentials, "access_token", allowedScope, url, nonce),
                RefreshToken = GenerateToken($"{tokenId}-refresh_token", user, application, signingCredentials, "refresh_token", allowedScope, url, nonce)
            };
        }

        public static string GenerateIdToken(string tokenId, User user, Application application, SigningCredentials signingCredentials, string[] scopes, string url, string? nonce)
        {
            var claims = new List<Claim> {
                new ("sub", user.Id),
                new ("jti", tokenId),
                new ("azp", application.ClientId ?? ""),
                new ("token_type", "id_token"),
                new ("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new ("scope", string.Join(" ",scopes)),
                new ("name", user.Name),
                new ("preferred_name", user.Id),
                new ("role", JsonConvert.SerializeObject(user.Roles ?? []), JsonClaimValueTypes.JsonArray)
            };

            if (nonce is not null)
            {
                claims.Add(new("nonce", nonce.ToString()));
            }

            if (scopes.Contains("email"))
            {
                claims.Add(new("email", user.Email ?? ""));
                claims.Add(new("email_verified", user.EmailVerified.ToString(), ClaimValueTypes.Boolean));
            }

            if (scopes.Contains("phone"))
            {
                claims.Add(new("phone", user.Phone?.Replace(" ", "") ?? ""));
            }

            var jwtToken = new JwtSecurityToken(
                 issuer: url,
                 audience: application.ClientId,
                 claims: claims,
                 notBefore: DateTime.Now,
                 expires: DateTime.Now.AddSeconds(application.ExpiredSecond),
                 signingCredentials
                );

            return new JwtSecurityTokenHandler().WriteToken(jwtToken);
        }

        public static string GenerateToken(string tokenId, User user, Application application, SigningCredentials signingCredentials, string tokenType, string[] scopes, string url, string? nonce)
        {
            var claims = new List<Claim> {
                new ("sub", user.Id) ,
                new ("jti", tokenId),
                new ("scope", string.Join(" ",scopes)),
                new ("token_type", tokenType),
                new ("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            };

            if (nonce is not null)
            {
                claims.Add(new("nonce", nonce.ToString()));
            }

            var expiredTime = DateTime.Now;
            if (tokenType == "access_token" || tokenType == "forget_password")
            {
                expiredTime = expiredTime.AddSeconds(application.AccessExpiredSecond);
            }
            else
            {
                expiredTime = expiredTime.AddSeconds(application.ExpiredSecond);
            }

            var jwtToken = new JwtSecurityToken(
                 issuer: url,
                 audience: application.ClientId,
                 claims: claims,
                 notBefore: DateTime.Now,
                 expires: expiredTime,
                 signingCredentials
                );

            return new JwtSecurityTokenHandler().WriteToken(jwtToken);
        }

        public static ClaimsPrincipal ValidateToken(string token, Application? app, string url)
        {
            if (app == null)
            {
                throw new ArgumentNullException("App not exist");
            }

            if (app.Cert == null)
            {
                throw new ArgumentNullException("Cert not exist");
            }

            var parsedSk = app.Cert.ToSecurityKey();

            var validateParameter = new TokenValidationParameters()
            {
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = url,
                ValidAudience = app.ClientId,
                IssuerSigningKey = parsedSk,
                ClockSkew = TimeSpan.Zero//校验过期时间必须加此属性
            };

            return new JwtSecurityTokenHandler().ValidateToken(token, validateParameter, out SecurityToken validatedToken);
        }
    }
}
