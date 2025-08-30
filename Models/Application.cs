using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
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

    [Index(nameof(ClientId), IsUnique = true)]
    public class Application : BaseModel
    {
        [Required]
        public string? Name { get; set; }
        public string? DisplayName { get; set; }
        public string? FaviconUrl { get; set; }
        public string? LogoUrl { get; set; }
        public string? LogoDarkUrl { get; set; }
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
        public List<ProviderItem> ProviderItems { get; set; } = [];
        public ApplicationTheme Theme { get; set; } = new ApplicationTheme();
        public Cert? Cert { get; set; }
        [NotMapped]
        public List<Provider> Providers { get; set; } = [];

        public Object getMaskedApplication()
        {
            return new
            {
                Id,
                Name,
                ClientId,
                FaviconUrl,
                LogoUrl,
                LogoDarkUrl,
                Scopes,
                ProviderItems,
                Providers,
                Theme
            };
        }
    }
}
