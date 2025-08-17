using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AuthCenter.Handler
{
    public class UserRoleAuthorizationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {

        private readonly IDistributedCache _cache;
        private readonly AuthCenterDbContext _authCenterDbContext;

        private int _failCode = StatusCodes.Status403Forbidden;

        public UserRoleAuthorizationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDistributedCache cache, AuthCenterDbContext authCenterDbContext) : base(options, logger, encoder)
        {
            _cache = cache;
            _authCenterDbContext = authCenterDbContext;
        }

        public const string UserRoleSchemeName = "UserRoleAuthorization";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = Request.Headers.Authorization.ToString();
            if (string.IsNullOrEmpty(token))
            {
                _failCode = StatusCodes.Status401Unauthorized;
                return Task.FromResult(AuthenticateResult.Fail("token不能为空"));
            }

            string userStr = _cache.GetString($"Login:Auth:{token}") ?? "";
            if (string.IsNullOrEmpty(userStr))
            {
                _failCode = StatusCodes.Status401Unauthorized;
                return Task.FromResult(AuthenticateResult.Fail("token不能为空"));
            }


            var user = JsonSerializer.Deserialize<CachedUser>(userStr);
            var dbUser = _authCenterDbContext.User.Find(user?.Id);

            if (dbUser is null || user is null)
            {
                _failCode = StatusCodes.Status401Unauthorized;
                return Task.FromResult(AuthenticateResult.Fail("token错误"));
            }

            dbUser.loginApplication = user.LoginApplication;

            var gi = new GenericIdentity(dbUser.Id);
            var principal = new ClaimsPrincipal();

            var claimList = new List<Claim>();

            if (dbUser.IsAdmin)
            {
                claimList.Add(new(ClaimTypes.Role, "admin"));
            }
            else
            {
                claimList.Add(new(ClaimTypes.Role, "user"));
            }
            claimList.Add(new(ClaimTypes.Name, dbUser.Name));

            principal.AddIdentity(new(gi, claimList));

            Context.Items["user"] = dbUser;

            return Task.FromResult(AuthenticateResult.Success(new(principal, UserRoleSchemeName)));
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var result = base.HandleChallengeAsync(properties);
            return base.HandleChallengeAsync(properties);
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var res = base.HandleForbiddenAsync(properties);
            Response.StatusCode = _failCode;
            return res;
        }
    }
}
