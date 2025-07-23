using AuthCenter.Models;
using Microsoft.IdentityModel.Tokens;
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

        public static JwtTokenPack GenerateCodeToken(Cert cert, User user, Application application, string url, string scopes, string? nonce)
        {
            var scopeList = scopes.Split(' ');
            var allowedScope = application.Scopes?.Intersect(scopeList).ToArray() ?? [];

            var certKey = cert.ToSecurityKey();
            var signTp = cert.CryptoAlgorithm + cert.CryptoSHASize.ToString();
            var signingCredentials = new SigningCredentials(certKey, cert.CryptoAlgorithm + cert.CryptoSHASize.ToString());

            return new JwtTokenPack
            {
                IdToken = GenerateIdToken(user, application, signingCredentials, allowedScope, url, nonce),
                AccessToken = GenerateToken(user, application, signingCredentials, "access_token", allowedScope, url, nonce),
                RefreshToken = GenerateToken(user, application, signingCredentials, "refresh_token", allowedScope, url, nonce)
            };
        }

        public static string GenerateIdToken(User user, Application application, SigningCredentials signingCredentials, string[] scopes, string url, string? nonce)
        {
            var jtiId = Guid.NewGuid();
            var claims = new List<Claim> {
                new ("sub", user.Number) ,
                new ("jti", jtiId.ToString()),
                new ("tokenType", "id_token"),
                new ("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
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
                claims.Add(new("phone", user.Phone ?? ""));
            }

            if (user.Roles != null)
            {
                foreach (var role in user.Roles)
                {
                    claims.Add(new Claim("role", role));
                }
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

        public static string GenerateToken(User user, Application application, SigningCredentials signingCredentials, string tokenType, string[] scopes, string url, string? nonce)
        {
            var jtiId = Guid.NewGuid();
            var claims = new List<Claim> {
                new ("sub", user.Number) ,
                new ("jti", jtiId.ToString()),
                new ("scope", string.Join(" ",scopes)),
                new ("tokenType", tokenType),
                new ("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            };

            if (nonce is not null)
            {
                claims.Add(new("nonce", nonce.ToString()));
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
    }
}
