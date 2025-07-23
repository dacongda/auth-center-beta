using AuthCenter.Models;
using JWT;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml.Linq;
using System.Linq;

namespace AuthCenter.Handler
{
    public class UserRoleAuthorizationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {

        private readonly IDistributedCache _cache;

        public UserRoleAuthorizationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDistributedCache cache) : base(options, logger, encoder)
        {
            _cache = cache;
        }

        public const string UserRoleSchemeName = "UserRoleAuthorization";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = Request.Headers["Authorization"].ToString();

            if (string.IsNullOrEmpty(token))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            string userStr = _cache.GetString(token) ?? "";
            if (string.IsNullOrEmpty(userStr)) {
                return Task.FromResult(AuthenticateResult.Fail("token不能为空"));
            }

            
            User? user = JsonSerializer.Deserialize<User>(userStr);


            if (user != null)
            {
                var gi = new GenericIdentity(user.Number);
                var principal = new ClaimsPrincipal();

                var claimList = new List<Claim>();

                if (user.Roles != null) {
                    claimList.AddRange(from role in user.Roles select new Claim( ClaimTypes.Role, role));
                }
                claimList.Add(new(ClaimTypes.Name, user.Name));

                principal.AddIdentity(new(gi,claimList));

                return Task.FromResult(AuthenticateResult.Success(new (principal, UserRoleSchemeName)));
            }

            return Task.FromResult(AuthenticateResult.Fail("token错误"));
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var result = base.HandleChallengeAsync(properties);
            return base.HandleChallengeAsync(properties);
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var res = base.HandleForbiddenAsync(properties);
            return base.HandleForbiddenAsync(properties);
        }
    }
}
