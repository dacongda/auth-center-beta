using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.Models;
using AuthCenter.Providers.StorageProvider;
using AuthCenter.ViewModels;
using AuthCenter.ViewModels.Request;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.Extensions.Caching.Distributed;
using NPOI.XSSF.UserModel;
using SkiaSharp;
using System.ComponentModel.DataAnnotations;
using System.Linq.Expressions;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        private readonly IDistributedCache _cache;
        private readonly AuthCenterDbContext _authCenterDbContext;
        private readonly IConfiguration _configuration;

        public UserController(ILogger<UserController> logger, IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IConfiguration configuration)
        {
            _logger = logger;
            _cache = cache;
            _authCenterDbContext = authCenterDbContext;
            _configuration = configuration;
        }

        [HttpGet("list", Name = "GetUserList")]
        [Authorize(Roles = "admin")]
        public JSONResult List(int page, int pageSize, string? parentChain, string? sortBy, string? sortOrder)
        {

            var countQuery = _authCenterDbContext.User.AsQueryable();
            var query = _authCenterDbContext.User.Include(u => u.Group)
                .Select(user => new { user.Id, user.Email, user.Name, user.Phone, user.GroupId, groupName = user.Group!.Name, isAdmin = user.IsAdmin });
            if (parentChain != null)
            {
                var groupIds = (from g in _authCenterDbContext.Group where g.ParentChain.StartsWith(parentChain + '/') || g.ParentChain == parentChain select g.Id).ToList();
                countQuery = countQuery.Where(u => groupIds.Contains(u.GroupId ?? 0));
                query = query.Where(u => groupIds.Contains(u.GroupId ?? 0));
            }
            var count = countQuery.Count();
            var list = query.Skip((page - 1) * pageSize)
                .Take(pageSize).ToList();
            return JSONResult.ResponseList(list, count);
        }

        [HttpGet(Name = "GetUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Get(string id)
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

            var state = _authCenterDbContext.User.Upsert(user).On(c => c.Id).Run();

            return JSONResult.ResponseOk("成功");
        }

        [HttpPost("importUser", Name = "ImportUser")]
        [Authorize(Roles = "admin")]
        public JSONResult ImportUser([FromForm] int groupId)
        {
            var file = Request.Form.Files[0];
            var workbook = new XSSFWorkbook(file.OpenReadStream());
            if (workbook == null)
            {
                return JSONResult.ResponseError("空Excel");
            }
            var sheet = workbook.GetSheetAt(0);

            var headerRow = sheet.GetRow(sheet.FirstRowNum);
            Dictionary<string, int> headerDict = [];
            for (var i = 0; i < headerRow.LastCellNum; i++)
            {
                var cellVal = headerRow.GetCell(i).ToString();
                if (String.IsNullOrEmpty(cellVal))
                {
                    continue;
                }

                headerDict.Add(cellVal, i);
            }

            var userType = typeof(User);
            var fields = userType.GetProperties();

            var addUserList = new List<User>();
            var failUserList = new List<User>();

            for (var i = 1; i <= sheet.LastRowNum; i++)
            {
                var row = sheet.GetRow(i);
                var user = new User();

                foreach (var field in fields)
                {
                    if (!headerDict.ContainsKey(field.Name))
                    {
                        continue;
                    }

                    var key = headerDict[field.Name];

                    object? cellVal = "";
                    if (field.PropertyType == typeof(string))
                    {
                        cellVal = row.GetCell(key)?.ToString() ?? null;
                    }
                    else if (field.PropertyType == typeof(int) || field.PropertyType == typeof(int?))
                    {
                        cellVal = (int)row.GetCell(key).NumericCellValue;
                    }
                    else if (field.PropertyType == typeof(bool) || field.PropertyType == typeof(bool?))
                    {
                        cellVal = row.GetCell(key).ToString() == "T";
                    }
                    else if (field.PropertyType == typeof(string[]))
                    {
                        var cellStr = row.GetCell(key).ToString() ?? "";
                        if (cellStr == "")
                        {
                            cellVal = Array.Empty<string>();
                        }
                        else
                        {
                            cellVal = cellStr.Split(",");
                        }

                    }
                    else
                    {
                        continue;
                    }

                    field.SetValue(user, cellVal);
                }

                if (String.IsNullOrEmpty(user.Id)) continue;
                user.GroupId = groupId;

                var context = new ValidationContext(user);
                var validationResults = new List<ValidationResult>();
                bool isValid = Validator.TryValidateObject(user, context, validationResults, true);

                if (!isValid)
                {
                    failUserList.Add(user);
                    continue;
                }

                addUserList.Add(user);
            }

            var upsertedUser = _authCenterDbContext.User.UpsertRange(addUserList).On(u => u.Id).RunAndReturn();

            return JSONResult.ResponseOk(new
            {
                SuccessImportList = upsertedUser.Select(u => new { u.Id, u.Name, u.Email, u.Phone, u.Roles, u.IsAdmin }),
                FailImportList = failUserList.Select(u => new { u.Id, u.Name, u.Email, u.Phone, u.Roles, u.IsAdmin }),
            });
        }

        [HttpPut(Name = "UpdateUser")]
        [Authorize(Roles = "admin,user")]
        public JSONResult Update(User user)
        {
            if (User.IsInRole("user") && User.Identity?.Name != user.Id)
            {
                return JSONResult.ResponseError("无权修改");
            }

            Expression<Func<SetPropertyCalls<User>, SetPropertyCalls<User>>> setPropertyCalls =
                b => b.SetProperty(u => u.Name, user.Name);

            if (user.IsAdmin)
            {
                setPropertyCalls = setPropertyCalls.Append(s =>
                        s.SetProperty(u => u.Id, user.Id)
                        .SetProperty(u => u.Roles, user.Roles)
                        .SetProperty(u => u.Email, user.Email)
                        .SetProperty(u => u.Phone, user.Phone)
                        .SetProperty(u => u.GroupId, user.GroupId)
                        .SetProperty(u => u.IsAdmin, user.IsAdmin));
            }

            _authCenterDbContext.User.Where(u => u.Id == user.Id).ExecuteUpdate(setPropertyCalls);

            return JSONResult.ResponseOk("成功");
        }

        [HttpPost("updateSafeInfo", Name = "UpdateSafeInfo")]
        public async Task<JSONResult> UpdateSafeInfo(ModifySafeInfoRequest request)
        {
            var userId = await _cache.GetStringAsync($"Auth:Verify:{request.Type}:{request.VerifyCode}");
            if (userId != User.Identity!.Name)
            {
                return JSONResult.ResponseError("认证失效");
            }

            var curUser = HttpContext.Items["user"] as User;

            var app = await _authCenterDbContext.Application.FindAsync(curUser!.loginApplication);
            var providerItem = (from pItem in app?.ProviderItems where pItem.Type == request.Type select pItem).FirstOrDefault();

            if (app == null)
            {
                return JSONResult.ResponseError("认证失效");
            }

            if (request.Type == "Email")
            {
                if (providerItem is not null)
                {
                    var secret = await _cache.GetStringAsync($"verification:email:{request.CodeId}");
                    if (String.IsNullOrEmpty(secret))
                    {
                        return JSONResult.ResponseError("认证失效");
                    }

                    var res = secret.Split(':');
                    var validTime = Convert.ToInt32(res[1]);
                    var code = res[0];
                    if (Convert.ToInt32(validTime) == 0)
                    {
                        await _cache.RemoveAsync($"verification:email:{request.CodeId}");
                        return JSONResult.ResponseError("验证码失效");
                    }


                    if (code != request.Code)
                    {
                        await _cache.SetStringAsync($"verification:email:{request.CodeId}", $"{code}:{validTime - 1}", new DistributedCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
                        });
                        return JSONResult.ResponseError("认证失效");
                    }
                }

                _authCenterDbContext.User.Where(u => u.Id == curUser.Id).ExecuteUpdate(s => s.SetProperty(u => u.Email, request.Email).SetProperty(u => u.EmailVerified, true));
                return JSONResult.ResponseOk();
            }
            else if (request.Type == "Phone")
            {
                if (providerItem is not null)
                {
                    // TODO: realize phone verification
                    return JSONResult.ResponseError("尚未实现");
                }

                _authCenterDbContext.User.Where(u => u.Id == curUser.Id).ExecuteUpdate(s => s.SetProperty(u => u.Phone, request.Phone).SetProperty(u => u.PhoneVerified, true));
                return JSONResult.ResponseOk();
            }
            else if (request.Type == "Password")
            {
                var encryptedPassword = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
                _authCenterDbContext.User.Where(u => u.Id == curUser.Id).ExecuteUpdate(s => s.SetProperty(u => u.Password, encryptedPassword));
                return JSONResult.ResponseOk();
            }

            return JSONResult.ResponseError("未知类型");
        }

        [HttpPost("updateAvatar", Name = "UpdateAvatar")]
        public async Task<JSONResult> UpdateAvatar()
        {
            var avatarFile = Request.Form.Files.FirstOrDefault();
            if (avatarFile is null)
            {
                return JSONResult.ResponseError("未携带文件");
            }

            if (avatarFile.Length > 1024 * 1024 * 2)
            {
                return JSONResult.ResponseError("图片过大");
            }

            if (HttpContext.Items["user"] is not User user)
            {
                return JSONResult.ResponseError("服务器错误");
            }

            var app = await _authCenterDbContext.Application.FindAsync(user.loginApplication);
            if (app == null)
            {
                return JSONResult.ResponseError("无此应用");
            }

            var storageProviderItem = app.ProviderItems.Where(pItem => pItem.Type == "Storage").FirstOrDefault();
            if (storageProviderItem == null)
            {
                return JSONResult.ResponseError("无存储提供商");
            }

            var dbStorageProvider = await _authCenterDbContext.Provider.FindAsync(storageProviderItem.ProviderId);
            if (dbStorageProvider == null)
            {
                return JSONResult.ResponseError("无存储提供商");
            }

            var baseDir = _configuration["baseDir"] ?? "upload";
            var storageProvider = IStorageProvider.GetStorageProvider(dbStorageProvider, baseDir);

            using var bitMap = SKBitmap.Decode(avatarFile.OpenReadStream());
            using var image = SKImage.FromBitmap(bitMap.Resize(new SKSizeI(128, 128), SKSamplingOptions.Default));
            using var data = image.Encode(SKEncodedImageFormat.Webp, 75);
            Stream savedFile = data.AsStream();

            var fileInfo = await storageProvider.AddFile(savedFile, "", "webp");

            var uploadFile = new UploadFile
            {
                Filename = fileInfo.Name,
                Filepath = fileInfo.Path,
                Extension = "webp",
                ProviderId = dbStorageProvider.Id,
            };

            _authCenterDbContext.Add(uploadFile);
            await _authCenterDbContext.SaveChangesAsync();

            var affected = await _authCenterDbContext.User
                .Where(u => u.Id == User.Identity!.Name)
                .ExecuteUpdateAsync(u => u.SetProperty(u => u.Avatar, fileInfo.Path));

            if (affected == 0)
            {
                return JSONResult.ResponseError("更新失败");
            }

            return JSONResult.ResponseOk();
        }

        [HttpPost("unBindThirdPart", Name = "UnBindThirdPart")]
        [Authorize(Roles = "admin,user")]
        public async Task<JSONResult> UnBindThirdPart(UserThirdpartInfo userThirdpartInfo)
        {
            if (userThirdpartInfo.UserId != User.Identity!.Name && !User.IsInRole("admin"))
            {
                return JSONResult.ResponseError("无权操作");
            }

            var res = await _authCenterDbContext.UserThirdpartInfos
                .Where(uti => uti.ProviderName == userThirdpartInfo.ProviderName && uti.UserId == userThirdpartInfo.UserId)
                .ExecuteDeleteAsync();

            if (res != 1)
            {
                return JSONResult.ResponseError("删除失败");
            }
            return JSONResult.ResponseOk();
        }

        [HttpDelete(Name = "DeleteUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Delete(string id)
        {
            if (id == "admin")
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

        [HttpGet("myInfo", Name = "GetMyInfo")]
        [Authorize(Roles = "admin,user")]
        public JSONResult GetMyInfo()
        {
            if (User.Identity == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户信息无效");
            }
            var user = _authCenterDbContext.User.Where(u => u.Id == User.Identity.Name).Include(p => p.Group).FirstOrDefault();
            if (user == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户无效");
            }
            if (user.Group != null)
            {
                var parentGroupNames = user.Group.Name.Split('/');
                var groupChainRoleList = _authCenterDbContext.Group
                    .Where(u => parentGroupNames.Contains(u.Name))
                    .Select(u => u.DefaultRoles).AsNoTracking().ToArray();
                foreach (var groupChainRole in groupChainRoleList)
                {
                    user.Roles = [.. user.Roles.Union(groupChainRole)];
                }
            }

            user.Password = "";
            user.Group = null;
            user.TotpSecret = "";

            return JSONResult.ResponseOk(user);
        }

        [HttpGet("myThirdPartBind", Name = "GetMyThirdPartBind")]
        [Authorize(Roles = "admin,user")]
        public async Task<JSONResult> GetMyThirdPartBind()
        {
            if (User.Identity == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户信息无效");
            }

            var thirdPartBind = await _authCenterDbContext.UserThirdpartInfos.Where(uti => uti.UserId == User.Identity.Name).AsNoTracking().ToListAsync();
            return JSONResult.ResponseOk(thirdPartBind);
        }

        [HttpGet("info", Name = "user-info")]
        [Authorize(Roles = "admin,user")]
        public JSONResult Info()
        {
            if (User.Identity == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户信息无效");
            }
            var user = HttpContext.Items["user"] as User;
            var application = _authCenterDbContext.Application.Find(user!.loginApplication);
            if (application == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户信息无效");
            }

            var appProviderItems = (from pItem in application.ProviderItems where pItem.Type == "Captcha" || pItem.Type == "Auth" select pItem.ProviderId).ToList();
            if (appProviderItems.Any())
            {
                application.Providers = [.. _authCenterDbContext.Provider.Where(p => appProviderItems.Contains(p.Id)).Select(p => new Provider{
                    Id = p.Id,
                    Name = p.Name,
                    DisplayName = p.DisplayName,
                    Type = p.Type,
                    SubType = p.SubType,
                    FaviconUrl = p.FaviconUrl,
                    ClientId = p.ClientId,
                    AuthEndpoint = p.AuthEndpoint,
                    Scopes = p.Scopes
                })];
            }

            return JSONResult.ResponseOk(new
            {
                realName = user.Name,
                roles = new List<string>() { user.IsAdmin ? "admin" : "user" },
                userId = user.Id,
                username = user.Name,
                id = user.Id,
                avatar = user.Avatar,
                loginApplication = application.getMaskedApplication()
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
                sub = user.Id,
                name = user.Name,
                email = user.Email,
                email_verified = user.EmailVerified
            });
        }
    }
}
