using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.Models;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using JWT.Builder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Collections;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection.Metadata;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        private readonly IDistributedCache _cache;
        private readonly AuthCenterDbContext _authCenterDbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;

        public UserController(ILogger<UserController> logger, IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
        {
            _logger = logger;
            _cache = cache;
            _authCenterDbContext = authCenterDbContext;
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

        [HttpGet("list", Name = "GetUserList")]
        [Authorize(Roles = "admin")]
        public JSONResult List(int page, int pageSize, string? parentChain, string? sortBy, string? sortOrder)
        {

            var countQuery = _authCenterDbContext.User.AsQueryable();
            var query = _authCenterDbContext.User.Include(u => u.Group)
                .Select(user => new { user.Id, user.Number, user.Email, user.Name, user.Phone, user.GroupId, groupName = user.Group.Name });
            if (parentChain != null)
            {
                var groupIds = (from g in _authCenterDbContext.Group where g.ParentChain.StartsWith(parentChain) select g.Id).ToList();
                countQuery = countQuery.Where(u => groupIds.Contains(u.Id));
                query = query.Where(u => groupIds.Contains(u.GroupId ?? 0));
            }
            var count = countQuery.Count();
            var list = query.Skip((page - 1) * pageSize)
                .Take(pageSize).ToList();
            return JSONResult.ResponseList(list, count);
        }

        [HttpGet(Name ="GetUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Get(int id)
        {
            var user = _authCenterDbContext.User.Where(u => u.Id == id).First();
            if (user == null)
            {
                return JSONResult.ResponseError("无此用户");
            }
            user.Password = "";
            return JSONResult.ResponseOk(user);
        }

        [HttpPost(Name = "AddUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Add(User user)
        {
            _logger.LogInformation(User.Identity?.Name ?? "fail");

            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);

            var state = _authCenterDbContext.User.Upsert(user).On(c => c.Number).Run();
            //_authCenterDbContext.SaveChanges();

            return JSONResult.ResponseOk("成功");
        }

        [HttpPut(Name = "UpdateUser")]
        [Authorize(Roles = "admin,user")]
        public JSONResult Update(User user)
        {
            if (User.IsInRole("user") && User.Identity?.Name != user.Number)
            {
                return JSONResult.ResponseError("无权修改");
            }


            _authCenterDbContext.User.Where(u => u.Number == user.Number).ExecuteUpdate(
                s => s.SetProperty(u => u.Number, user.Number)
                .SetProperty(u => u.Roles, user.Roles)
                .SetProperty(u => u.Email, user.Email)
                .SetProperty(u => u.Phone, user.Phone)
                .SetProperty(u => u.GroupId, user.GroupId)
                .SetProperty(u => u.Name, user.Name)
                );

            return JSONResult.ResponseOk("成功");
        }

        [HttpDelete(Name = "DeleteUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Delete(int id)
        {
            if (id == 1)
            {
                return JSONResult.ResponseError("无法删除主管理，请尝试禁用功能");
            }

            var effected = _authCenterDbContext.User.Where(u => u.Id == id).ExecuteDelete();
            if (effected == 0)
            {
                return JSONResult.ResponseError("删除失败");
            }

            return JSONResult.ResponseOk("成功");
        }

        [HttpPost("login", Name = "Login")]
        public JSONResult Login(LoginUser loginUser)
        {
            //var loginType = Request.Query["type"];
            var responseType = Request.Query["response_type"];

            var user = _authCenterDbContext.User.Where(u => u.Number == loginUser.Name).Include(p => p.Group).First();
            if (user == null)
            {
                return JSONResult.ResponseError("无此用户");
            }

            try
            {
                if (!BCrypt.Net.BCrypt.Verify(loginUser.Password, user.Password))
                {
                    return JSONResult.ResponseError("密码错误");
                }
            }
            catch
            {
                return JSONResult.ResponseError("密码错误");
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

            var request = _httpContextAccessor.HttpContext.Request;

            var url = request.Scheme + "://" + request.Host.Value;
            var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            if (frontEndUrl == null || frontEndUrl == "")
            {
                frontEndUrl = url;
            }

            string[] oauthType = ["code", "code id_token", "id_token", "id_token token", "code id_token token"];

            // 登陆系统管理页
            if (responseType == "login")
            {
                var tokenString = user.Id.ToString() + ":" + Guid.NewGuid().ToString();

                _cache.SetString(tokenString, JsonSerializer.Serialize(user), new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(7)
                });

                return JSONResult.ResponseOk(
                    new LoginResult()
                    {
                        AccessToken = tokenString
                    });
            }
            else if (Array.IndexOf(oauthType, responseType) != -1)
            {
                // 使用oidc code登陆
                var clientId = Request.Query["client_id"];
                var redirectUrl = Request.Query["redirect_uri"];
                var scope = Request.Query["scope"];
                var state = Request.Query["state"].ToString();
                var nonce = Request.Query["nonce"].ToString();

                var curApplication = _authCenterDbContext.Application.Where(app => app.ClientId == clientId.ToString()).First();
                if (curApplication == null)
                {
                    return JSONResult.ResponseError("应用不存在");
                }

                var parsedRedirectUrl = new Uri(redirectUrl.ToString());

                var targetRedirect = curApplication.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == parsedRedirectUrl.Host)
                    .First();
                if (targetRedirect == null)
                {
                    return JSONResult.ResponseError("目标地址不在许可地址内");
                }

                Dictionary<string, string> dict = new();
                if (responseType.Contains("code")) { 
                    var code = Guid.NewGuid().ToString();
                    code = Base64UrlEncoder.Encode(code);

                    _cache.SetString(code, JsonSerializer.Serialize(new
                    {
                        nonce,
                        state,
                        user,
                    }), new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(120),
                    });

                    dict["code"] = code;
                }

                if (responseType.Contains("id_token") || responseType.Contains("token"))
                {
                    var tokenPack = TokenUtil.GenerateCodeToken(curApplication.Cert, user, curApplication, url, scope, nonce);
                    if(responseType.Contains("id_token"))
                    {
                        dict["id_token"] = tokenPack.IdToken;
                    }

                    if (responseType.Contains("token"))
                    {
                        dict["token"] = tokenPack.AccessToken;
                    }
                }

                return JSONResult.ResponseOk(dict);
            } else if (responseType == "saml")
            {
                var rawSamlRequest = Request.Query["SAMLRequest"];
                var clientId = Request.Query["client_id"];

                var samlRequest = Utils.SamlUtil.ParseSamlRequest(rawSamlRequest);

                var curApplication = _authCenterDbContext.Application.Where(app => app.ClientId == clientId.ToString()).Include(app => app.Cert).First();
                if (curApplication == null)
                {
                    return JSONResult.ResponseError("应用不存在");
                }

                var redirectUri = new Uri(samlRequest.AssertionConsumerServiceURL);

                var targetRedirect = curApplication.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == redirectUri.Host)
                    .First();
                if (targetRedirect == null)
                {
                    return JSONResult.ResponseError("目标地址不在许可地址内");
                }

                var respId = Guid.NewGuid().ToString("N");
                var samlResponse = Utils.SamlUtil.GetSAMLResponse(user, curApplication, url, frontEndUrl, samlRequest.AssertionConsumerServiceURL, samlRequest.Issuer, respId, samlRequest.ID);
                return JSONResult.ResponseOk(new
                {
                    samlResponse = samlResponse,
                    samlBindingType = samlRequest.ProtocolBinding,
                    redirectUrl = samlRequest.AssertionConsumerServiceURL
                });
            }

            return JSONResult.ResponseError("登陆类型错误");
        } 

        [HttpGet("info", Name = "user-info")]
        [Authorize(Roles = "admin,user")]
        public JSONResult Info()
        {
            if (User.Identity == null)
            {
                return JSONResult.ResponseError("用户信息无效");
            }
            var user = _authCenterDbContext.User.Where(u => u.Number == User.Identity.Name).Include(p => p.Group).First();
            IEnumerable<string> roles = user.Roles;
            if (user.Group != null)
            {
                user.Roles = user.Roles.Union(user.Group.DefaultRoles).ToArray();
            }

            return JSONResult.ResponseOk(new
            {
                realName = user.Name,
                roles = user.Roles,
                userId = user.Number,
                username = user.Name,
            });
        }

        [HttpGet("userinfo", Name = "token-userinfo")]
        [Authorize(AuthenticationSchemes = BearerAuthorizationHandler.BearerSchemeName, Roles = "admin,user")]
        public IActionResult UserInfo()
        {
            var user = HttpContext.Items["user"] as User;
            if (user == null)
            {
                Response.Headers.Append("WWW-Authenticate", "Bearer error=\"user not found\", error_description=\"User not found\"");
                return Unauthorized();
            }

            return Json(new
            {
                sub = user.Number,
                name = user.Name,
                email = user.Email,
            });
        }
    }
}
