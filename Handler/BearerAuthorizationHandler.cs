using AuthCenter.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.EntityFrameworkCore;
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
        private readonly HttpContext _httpContext;
        private string _failReason;
        private string _failReasonDescription;

        public BearerAuthorizationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, AuthCenterDbContext authCenterDbContext, IHttpContextAccessor httpContextAccessor) : base(options, logger, encoder)
        {
            _authCenterDbContext = authCenterDbContext;
            _httpContext = httpContextAccessor.HttpContext;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = Request.Headers["Authorization"].ToString();

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
                var clientId = tokenObj.Audiences.First();
                if (clientId == null)
                {
                    _failReason = "invalid_token";
                    _failReasonDescription = "App not exist";
                    return Task.FromResult(AuthenticateResult.Fail("app不存在"));
                }

                var app = _authCenterDbContext.Application.Where(app => app.ClientId == clientId).Include(p => p.Cert).First();
                if (app == null)
                {
                    _failReason = "invalid_token";
                    _failReasonDescription = "App not exist";
                    return Task.FromResult(AuthenticateResult.Fail("app不存在"));
                }

                if (app.Cert == null)
                {
                    _failReason = "invalid_token";
                    _failReasonDescription = "Cert error";
                    return Task.FromResult(AuthenticateResult.Fail("证书错误"));
                }

                var parsedSk = app.Cert.ToSecurityKey();

                var validateParameter = new TokenValidationParameters()
                {
                    ValidateLifetime = true,
                    ValidateAudience = true,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _httpContext.Request.GetDisplayUrl(),
                    ValidAudience = app.ClientId,
                    IssuerSigningKey = parsedSk,
                    ClockSkew = TimeSpan.Zero//校验过期时间必须加此属性
                };

                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

                _ = new JwtSecurityTokenHandler().ValidateToken(headerValue.Parameter, validateParameter, out SecurityToken validatedToken);

                var user = _authCenterDbContext.User.Where(user => user.Number == tokenObj.Subject).Include(p => p.Group).First();
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

                _httpContext.Items["user"] = user;
                _httpContext.Items["application"] = app;
                _httpContext.Items["scope"] = scope;

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