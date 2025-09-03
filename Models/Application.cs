using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace AuthCenter.Models
{
    public class ProviderItem
    {
        [JsonIgnore]
        public int FakeId { get; set; } = 1;
        public int ProviderId { get; set; }
        public string? Type { get; set; }
        public string[] Rule { get; set; } = [];
    }

    public class SamlAttribute
    {
        [JsonIgnore]
        public int FakeId { get; set; } = 1;
        public string Name { get; set; } = String.Empty;
        public string NameFormat { get; set; } = String.Empty;
        public string Value { get; set; } = String.Empty;
    }

    public class SamlRedirect
    {
        [JsonIgnore]
        public int FakeId { get; set; } = 1;
        public string Issuer { get; set; } = String.Empty;
        public string RedirectUrl { get; set; } = String.Empty;
    }

    public class ApplicationTheme
    {
        public string PrimaryColor { get; set; } = "hsl(212, 100%, 45%)";
        public string Radius { get; set; } = "0.5";
    }

    public class LoginMethod(string name, string rule)
    {
        [JsonIgnore]
        public int FakeId { get; set; } = 1;
        public string Name { get; set; } = name; 
        public string Rule { get; set; } = rule;
    }

    public class LoginFormSettingItem
    {
        public string? Style { get; set; } = "";
        public string? Rule { get; set; } = "";
        public bool? Visible { get; set; } = true;
    }

    public class LoginFormSetting
    {
        public LoginFormSettingItem? LoginPanel { get; set; } = default!;
        public LoginFormSettingItem? LoginBackground { get; set; } = default!;
        public LoginFormSettingItem? FormLogo { get; set; } = default!;
        public LoginFormSettingItem? Input { get; set; } = default!;
        public LoginFormSettingItem? LoginButton { get; set; } = default!;
        public LoginFormSettingItem? ThirdPartLogin { get; set; } = default!;
    }

    [Index(nameof(ClientId), IsUnique = true)]
    public class Application : BaseModel
    {
        [Required]
        public string? Name { get; set; }
        public string? DisplayName { get; set; }
        public string? FaviconUrl { get; set; }
        public string? LogoUrl { get; set; }
        public string? LogoDarkUrl { get; set; }
        public bool EnableAuthorizeConfirm { get; set; } = false;
        public int FailLoginLimit { get; set; } = 5;
        public int FailLoginForzenMinute { get; set; } = 15;
        [Required]
        public string? ClientId { get; set; }
        [Required]
        public string? ClientSecret { get; set; }
        [Required]
        public string[]? Scopes { get; set; }
        [Required]
        public int CertId { get; set; }
        public int[] GroupIds { get; set; } = [];
        public string[]? RedirectUrls { get; set; }
        public int ExpiredSecond { get; set; }
        public int AccessExpiredSecond { get; set; }
        public string[] SamlAudiences { get; set; } = [];
        public List<SamlRedirect> SamlRedirects { get; set; } = [];
        public List<SamlAttribute> SamlAttributes { get; set; } = [];
        public bool SamlResponseCompress { get; set; }
        public bool SamlEncrypt { get; set; }
        public List<LoginMethod> LoginMethods { get; set; } = [];
        public LoginFormSetting LoginFormSetting { get; set; } = default!;
        public List<ProviderItem> ProviderItems { get; set; } = [];
        public ApplicationTheme Theme { get; set; } = new ApplicationTheme();
        public Cert? Cert { get; set; }
        [NotMapped]
        public List<Provider> Providers { get; set; } = [];

        public object GetMaskedApplicationObj()
        {
            return new
            {
                Id,
                Name,
                ClientId,
                FaviconUrl,
                EnableAuthorizeConfirm,
                LogoUrl,
                LogoDarkUrl,
                Scopes,
                LoginMethods,
                LoginFormSetting,
                ProviderItems,
                Providers,
                Theme
            };
        }

        public Application GetMaskedApplication()
        {
            return new Application
            {
                Id = Id,
                Name = Name,
                ClientId = ClientId,
                FaviconUrl = FaviconUrl,
                EnableAuthorizeConfirm = EnableAuthorizeConfirm,
                LogoUrl = LogoUrl,
                LogoDarkUrl = LogoDarkUrl,
                Scopes = Scopes,
                LoginMethods = LoginMethods,
                LoginFormSetting = LoginFormSetting,
                ProviderItems = ProviderItems,
                Providers = Providers,
                Theme = Theme
            };
        }
    }
}
