using AuthCenter.Data;
using AuthCenter.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;

namespace AuthCenter.Handler
{
    public class BearerAuthorizationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string BearerSchemeName = "BearerSchemeAuthorization";
        private readonly AuthCenterDbContext _authCenterDbContext;
        private readonly IDistributedCache _cache;

        private string _failReason = "";
        private string _failReasonDescription = "";

        public BearerAuthorizationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, AuthCenterDbContext authCenterDbContext, IDistributedCache cache) : base(options, logger, encoder)
        {
            _authCenterDbContext = authCenterDbContext;
            _cache = cache;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = Request.Headers.Authorization.ToString();

            if (string.IsNullOrEmpty(token))
            {
                _failReason = "invalid_request";
                _failReasonDescription = "Empty token";
                return Task.FromResult(AuthenticateResult.Fail("Token为空"));
            }

            if (!AuthenticationHeaderValue.TryParse(token, out var headerValue))
            {
                _failReason = "invalid_request";
                _failReasonDescription = "Error header";
                return Task.FromResult(AuthenticateResult.Fail("错误的header"));
            }


            if (!"Bearer".Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                _failReason = "invalid_request";
                _failReasonDescription = "Error auth type";
                return Task.FromResult(AuthenticateResult.Fail("错误的认证方式"));
            }

            try
            {
                var tokenObj = new JwtSecurityToken(headerValue.Parameter);
                var jti = tokenObj.Claims.FirstOrDefault(c => c.Type == "jti")?.Value ?? "";
                var tokenId = jti.Split("-")[0];

                var isValid = _cache.GetString($"Login:OAuth:Token:{tokenId}");
                if (isValid == null) {
                    _failReason = "invalid_token";
                    _failReasonDescription = "Token expored";
                    return Task.FromResult(AuthenticateResult.Fail("Token expored"));
                }

                var clientId = tokenObj.Audiences.First();
                if (clientId == null)
                {
                    _failReason = "invalid_token";
                    _failReasonDescription = "App not exist";
                    return Task.FromResult(AuthenticateResult.Fail("app不存在"));
                }

                var app = _authCenterDbContext.Application.Where(app => app.ClientId == clientId).Include(p => p.Cert).First();

                try { 
                    _ = TokenUtil.ValidateToken(headerValue.Parameter!, app, Context.Request.GetDisplayUrl());
                } catch (Exception ex)
                {
                    _failReason = "invalid_token";
                    _failReasonDescription = ex.Message;
                    return Task.FromResult(AuthenticateResult.Fail("app不存在"));
                }

                var user = _authCenterDbContext.User.Where(user => user.Id == tokenObj.Subject).Include(p => p.Group).First();
                if (user == null)
                {
                    _failReason = "invalid_token";
                    _failReasonDescription = "User not exist";
                    return Task.FromResult(AuthenticateResult.Fail("用户不存在"));
                }

                if(user.IsAdmin)
                {
                    user.Roles.Append("admin");
                } else
                {
                    user.Roles.Append("user");
                }

                if (user.Group != null)
                {
                    var parentGroupNames = user.Group.Name.Split('/');
                    var groupChainRoleList = _authCenterDbContext.Group.Where(u => parentGroupNames.Contains(u.Name)).Select(u => u.DefaultRoles).ToArray();
                    foreach (var groupChainRole in groupChainRoleList)
                    {
                        user.Roles = [.. user.Roles.Union(groupChainRole)];
                    }
                }

                var scope = tokenObj.Claims.FirstOrDefault(c => c.Type == "scope");

                var gi = new GenericIdentity(tokenObj.Subject);
                var principal = new ClaimsPrincipal();
                var claimList = new List<Claim>();
                if (user.Roles != null)
                {
                    claimList.AddRange(from role in user.Roles select new Claim(ClaimTypes.Role, role));
                }
                claimList.Add(new(ClaimTypes.Name, user.Name));
                principal.AddIdentity(new(gi, claimList));

                Context.Items["user"] = user;
                Context.Items["application"] = app;
                Context.Items["scope"] = scope;
                Context.Items["tokenId"] = tokenId;

                return Task.FromResult(AuthenticateResult.Success(new(principal, BearerSchemeName)));
            }
            catch (SecurityException ex)
            {
                _failReason = "invalid_request";
                _failReasonDescription = ex.Message;
                return Task.FromResult(AuthenticateResult.Fail(ex.Message));
            }
            catch (Exception ex)
            {
                _failReason = "invalid_request";
                _failReasonDescription = ex.Message;
                return Task.FromResult(AuthenticateResult.Fail(ex.Message));
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers.Append("WWW-Authenticate", $"Bearer error=\"{_failReason}\", error_description=\"{_failReasonDescription ?? ""}\"");
            return base.HandleChallengeAsync(properties);
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            Response.Headers.Append("WWW-Authenticate", "Bearer error=\"insufficient_scope\", error_description=\"insufficient_scope\"");
            return base.HandleForbiddenAsync(properties);
        }

    }
}