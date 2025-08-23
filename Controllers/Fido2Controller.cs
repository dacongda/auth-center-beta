using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.ViewModels;
using AuthCenter.ViewModels.Request;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using System.Text;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "admin,user")]
    public class Fido2Controller(AuthCenterDbContext authCenterDbContext, IDistributedCache cache, IConfiguration configuration, ILogger<Fido2Controller> logger) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IDistributedCache _cache = cache;
        private readonly ILogger<Fido2Controller> _logger = logger;
        private readonly IConfiguration _configuration = configuration;

        private readonly string frontEndUrl = configuration["FrontEndUrl"] ?? "http://localhost";
        private readonly string serverDomain = new Uri(configuration["FrontEndUrl"] ?? "").Host;

        [HttpGet("getUserCredentials", Name = "GetUserCedentials")]
        public async Task<JSONResult> GetUserCredentials()
        {
            var creds = await _authCenterDbContext.WebAuthnCredential.Where(c => c.UserId == User.Identity!.Name).Select(c => new { c.Name, c.Id }).ToListAsync();
            return JSONResult.ResponseOk(creds);
        }

        [HttpGet("createOptions", Name = "GetFido2CreateOptions")]
        public JSONResult GetCreateOptions()
        {
            var dbUser = HttpContext.Items["user"] as User;

            var existingKeys = _authCenterDbContext.WebAuthnCredential.Where(c => c.UserId == User.Identity!.Name).ToList();

            var origins = new HashSet<string>() { "https://localhost", frontEndUrl };

            var fido2Config = new Fido2Configuration
            {
                ServerDomain = serverDomain,
                ServerName = "AuthCenter",
                Origins = origins,
                TimestampDriftTolerance = 300000,
            };

            var fido2 = new Fido2(fido2Config);

            var authenticatiorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Preferred,
                UserVerification = UserVerificationRequirement.Preferred,
            };

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                CredProps = true,
            };

            var user = new Fido2User
            {
                DisplayName = dbUser!.Name,
                Name = dbUser.Id,
                Id = Encoding.UTF8.GetBytes(dbUser.Id),
            };

            var options = fido2.RequestNewCredential(new RequestNewCredentialParams
            {
                User = user,
                ExcludeCredentials = [.. (from key in existingKeys select key.Descriptor)],
                Extensions = exts,
                AuthenticatorSelection = authenticatiorSelection,
                AttestationPreference = AttestationConveyancePreference.None
            });

            var optionId = "WebAuthn:Options:" + Guid.NewGuid().ToString("N");
            _cache.SetString(optionId, options.ToJson(), new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(2),
            });

            return JSONResult.ResponseOk(new
            {
                options,
                optionId,
            });
        }

        [HttpPost("createCredential", Name = "CreateCredential")]
        async public Task<JSONResult> CreateCredential(WebAuthnRequest<AuthenticatorAttestationRawResponse> attestationResponse)
        {
            var optionStr = await _cache.GetStringAsync(attestationResponse.CacheOptionId);
            if (optionStr == null)
            {
                return JSONResult.ResponseError("无此请求");
            }
            _ = _cache.RemoveAsync(attestationResponse.CacheOptionId);
            var option = CredentialCreateOptions.FromJson(optionStr);
            if (option == null)
            {
                return JSONResult.ResponseError("无此请求");
            }

            var origins = new HashSet<string>() { "https://localhost", "http://localhost:5888", frontEndUrl };
            var fido2Config = new Fido2Configuration
            {
                ServerDomain = serverDomain,
                ServerName = "AuthCenter",
                Origins = origins,
                TimestampDriftTolerance = 300000,
            };

            var fido2 = new Fido2(fido2Config);
            var credential = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse.RequestValue,
                OriginalOptions = option,
                IsCredentialIdUniqueToUserCallback = IsCredentialUniqueToUser
            });

            var storedCred = new WebAuthnCredential()
            {
                Id = Convert.ToBase64String(credential.Id),
                Name = Guid.NewGuid().ToString("N"),
                PublicKey = credential.PublicKey,
                UserId = User.Identity!.Name!,
                Transports = credential.Transports,
                IsBackedUp = credential.IsBackedUp,
                IsBackupEligible = credential.IsBackupEligible,
                AttestationObject = credential.AttestationObject,
                AttestationClientDataJson = credential.AttestationClientDataJson,
                RegDate = DateTime.UtcNow,
                AaGuid = credential.AaGuid,
                SignCount = 1,
            };

            _ = await _authCenterDbContext.WebAuthnCredential.AddAsync(storedCred);
            _ = await _authCenterDbContext.SaveChangesAsync();

            return JSONResult.ResponseOk(storedCred);
        }

        private async Task<bool> IsCredentialUniqueToUser(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken)
        {
            var base64Id = Convert.ToBase64String(args.CredentialId);
            var count = await _authCenterDbContext.WebAuthnCredential.Where(c => c.UserId == args.User.Name && c.Id == base64Id).CountAsync(cancellationToken: cancellationToken);
            return count == 0;
        }

        [HttpGet("getAssertionOptions", Name = "GetAssertion")]
        [AllowAnonymous]
        async public Task<JSONResult> GetAssertionOptions(string? id)
        {
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();
            if (id is not null)
            {
                var creds = await _authCenterDbContext.WebAuthnCredential.Where(c => c.UserId == id).ToListAsync();
                existingCredentials = (from cred in creds select cred.Descriptor).ToList();
            }

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
            };

            var origins = new HashSet<string>() { "https://localhost", frontEndUrl };

            var fido2Config = new Fido2Configuration
            {
                ServerDomain = serverDomain,
                ServerName = "AuthCenter",
                Origins = origins,
                TimestampDriftTolerance = 300000,
            };

            var fido2 = new Fido2(fido2Config);

            var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = existingCredentials,
                UserVerification = UserVerificationRequirement.Preferred,
                Extensions = exts
            });

            var optionId = "WebAuthn:Assertion:" + Guid.NewGuid().ToString("N");
            await _cache.SetStringAsync(optionId, options.ToJson(), new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(2),
            });

            return JSONResult.ResponseOk(new
            {
                options,
                optionId
            });
        }

        [HttpPost("createAssertion", Name = "CreateAssertion")]
        [AllowAnonymous]
        public async Task<JSONResult> CreateAssertion([FromBody] WebAuthnRequest<AuthenticatorAssertionRawResponse> clientResponse, CancellationToken cancellationToken)
        {
            var optionJson = await _cache.GetStringAsync(clientResponse.CacheOptionId, cancellationToken);
            if (optionJson == null)
            {
                return JSONResult.ResponseError("无此请求");
            }

            _ = _cache.RemoveAsync(clientResponse.CacheOptionId, cancellationToken);

            var origins = new HashSet<string>() { "https://localhost", "http://localhost:5888", frontEndUrl };
            var fido2Config = new Fido2Configuration
            {
                ServerDomain = serverDomain,
                ServerName = "AuthCenter",
                Origins = origins,
                TimestampDriftTolerance = 300000,
            };

            var fido2 = new Fido2(fido2Config);


            var options = AssertionOptions.FromJson(optionJson);
            var credtId = Convert.ToBase64String(clientResponse.RequestValue.RawId);

            var cred = await _authCenterDbContext.WebAuthnCredential.FirstOrDefaultAsync(k => k.Id == credtId, cancellationToken);
            if (cred is null)
            {
                return JSONResult.ResponseError("无此证书");
            }

            var user = await _authCenterDbContext.User.FirstAsync(u => u.Id == cred.UserId);

            IsUserHandleOwnerOfCredentialIdAsync callback = static (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            var res = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = clientResponse.RequestValue,
                OriginalOptions = options,
                StoredPublicKey = cred.PublicKey,
                StoredSignatureCounter = 1,
                IsUserHandleOwnerOfCredentialIdCallback = callback,
            }, cancellationToken);

            var cachePrefix = "WebAuthn:login:";
            if (clientResponse.AuthType != null) cachePrefix = $"WebAuthn:{clientResponse.AuthType}:";

            var webAuthLoginId = Guid.NewGuid().ToString("N");
            _logger.LogInformation(cachePrefix + webAuthLoginId);
            await _cache.SetStringAsync(cachePrefix + webAuthLoginId, user.Id, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(2),
            }, token: cancellationToken);

            return JSONResult.ResponseOk(new
            {
                res,
                webAuthLoginId,
            });
        }

        [HttpPut("updateCredName", Name = "UpdateCredName")]
        public async Task<JSONResult> UpdateCredName(WebAuthnCredential webAuthnCredential)
        {
            var cred = await _authCenterDbContext.WebAuthnCredential.Where(c => c.Id == webAuthnCredential.Id && c.UserId == User.Identity!.Name).FirstOrDefaultAsync();
            if (cred == null)
            {
                return JSONResult.ResponseError("无此证书");
            }

            cred.Name = webAuthnCredential.Name;
            _authCenterDbContext.Update(cred);
            _authCenterDbContext.SaveChanges();

            return JSONResult.ResponseOk("修改成功");
        }

        [HttpDelete("deleteCred", Name = "DeleteCred")]
        public async Task<JSONResult> DeleteCred(string id)
        {
            var effected = await _authCenterDbContext.WebAuthnCredential.Where(c => c.Id == id && c.UserId == User.Identity!.Name).ExecuteDeleteAsync();
            if (effected != 1)
            {
                return JSONResult.ResponseError("无此证书");
            }

            return JSONResult.ResponseOk("删除成功");
        }
    }
}
