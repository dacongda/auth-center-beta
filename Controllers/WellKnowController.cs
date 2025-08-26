using AuthCenter.Data;
using AuthCenter.Utils;
using AuthCenter.ViewModels.Response;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route(".well-known")]
    public class WellKnowController(AuthCenterDbContext authCenterDbContext, IConfiguration configuration) : Controller
    {

        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration = configuration;
        private string RequestUrl => ControllerUtils.GetFrontUrl(_configuration, Request);

        [HttpGet("openid-configuration", Name = "openid-configuration")]
        public IActionResult OpenidConfiguration()
        {
            //var url = Request.Scheme + "://" + Request.Host.Value;
            //var frontEndUrl = _configuration["frontEndUrl"];
            //if (frontEndUrl == null || frontEndUrl == "")
            //{
            //    frontEndUrl = url;
            //}

            var config = new OpenidConfiguration
            {
                issuer = RequestUrl,
                authorization_endpoint = RequestUrl + "/auth/login",
                token_endpoint = RequestUrl + "/api/oauth/token",
                userinfo_endpoint = RequestUrl + "/api/user/userinfo",
                jwks_uri = RequestUrl + "/.well-known/jwks",
                introspection_endpoint = RequestUrl + "/api/oauth/introspect",
                end_session_endpoint = RequestUrl + "/api/auth/logout",
                scopes_supported = ["phone", "email", "profile"],
                response_types_supported = ["code", "code id_token", "id_token", "id_token token", "code id_token token"],
                response_modes_supported = ["query", "fragment", "form_post"],
                grant_types_supported = ["authorization_code", "implicit", "refresh_token"],
                subject_types_supported = ["public"],
                id_token_signing_alg_values_supported = ["RS256", "RS512", "ES256", "ES384", "ES512"],
                claims_supported = ["sub", "iss", "jti", "nbf", "aud", "iat", "exp", "name", "profile", "email", "email_verified", "phone", "phone_verified"],
                request_object_signing_alg_values_supported = ["HS256", "HS384", "HS512"],
                request_parameter_supported = true,
            };
            return Json(config);
        }

        [HttpGet("jwks", Name = "jwks")]
        public IActionResult Jwks()
        {
            var certs = _authCenterDbContext.Cert.Where(cert => cert.Type == "jwk");
            var jsonWebKeys = new List<JsonWebKey>();

            foreach (var cert in certs)
            {
                if (cert.CryptoAlgorithm == "RS")
                {
                    jsonWebKeys.Add(JsonWebKeyConverter.ConvertFromX509SecurityKey(new X509SecurityKey(cert.ToX509Certificate2()), true));
                }
                else if (cert.CryptoAlgorithm == "ES")
                {
                    jsonWebKeys.Add(JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(cert.ToX509Certificate2().GetECDsaPrivateKey())));
                }
            }

            return Json(new
            {
                keys = jsonWebKeys
            });
        }
    }
}
