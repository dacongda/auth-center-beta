using AuthCenter.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;

namespace AuthCenter.Handler
{
    public class BasicAuthorizationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly AuthCenterDbContext _authCenterDbContext;
        public BasicAuthorizationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, AuthCenterDbContext authCenterDbContext, IHttpContextAccessor httpContextAccessor) : base(options, logger, encoder)
        {
            _authCenterDbContext = authCenterDbContext;
        }

        public const string BasicSchemeName = "BasicAuthorization";
        private string _failReason = "";
        private string _failReasonDescription = "";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var basic = Request.Headers.Authorization.ToString();
            if (string.IsNullOrEmpty(basic))
            {
                _failReason = "invalid_client";
                _failReasonDescription = "Empty auth field";
                return Task.FromResult(AuthenticateResult.Fail("未登录"));
            }

            if (!AuthenticationHeaderValue.TryParse(basic, out var headerValue))
            {
                _failReason = "invalid_client";
                _failReasonDescription = "Empty auth field";
                return Task.FromResult(AuthenticateResult.Fail("错误的header"));
            }

            if (!"Basic".Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                _failReason = "invalid_request";
                _failReasonDescription = "Empty auth field";
                return Task.FromResult(AuthenticateResult.Fail("错误的认证方式"));
            }

            var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(headerValue.Parameter ?? "")).Split(':', 2);

            if (credentials.Length != 2)
            {
                _failReason = "invalid_request";
                _failReasonDescription = "Error encoding";
                return Task.FromResult(AuthenticateResult.Fail("编码错误"));
            }

            var clientId = credentials[0];
            var clientSecret = credentials[1];

            try
            {
                var application = _authCenterDbContext.Application.Where(app => app.ClientId == clientId && app.ClientSecret == clientSecret).Include(p => p.Cert).First();
                if (application == null)
                {
                    _failReason = "invalid_client";
                    _failReasonDescription = "invalid_client";
                    return Task.FromResult(AuthenticateResult.Fail("账户名或密码错误"));
                }


                var gi = new GenericIdentity("app:" + application.Name);
                var principal = new ClaimsPrincipal();
                var claimList = new List<Claim>() { new(ClaimTypes.Role, "app") };
                //claimList.Add(new Claim(ClaimTypes.Role, "app"));

                principal.AddIdentity(new(gi, claimList));

                Context.Items["application"] = application;

                return Task.FromResult(AuthenticateResult.Success(new(principal, BasicSchemeName)));
            }
            catch (Exception)
            {
                _failReason = "invalid_client";
                _failReasonDescription = "invalid_client";
                return Task.FromResult(AuthenticateResult.Fail("账户名或密码错误"));
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var errorResp = new
            {
                error = _failReason,
                error_description = _failReasonDescription
            };


            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Response.WriteAsync(JsonConvert.SerializeObject(errorResp));
            //Response.Headers.Append("WWW-Authenticate", $"Bearer error=\"{_failReason}\", error_description=\"{_failReasonDescription ?? ""}\"");
            //return base.HandleChallengeAsync(properties);
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var res = base.HandleForbiddenAsync(properties);
            return base.HandleForbiddenAsync(properties);
        }
    }
}
