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

    [Index(nameof(ClientId), IsUnique = true)]
    public class Application : BaseModel
    {
        [Required]
        public string? Name { get; set; }
        [Required]
        public string? ClientId { get; set; }
        [Required]
        public string? ClientSecret { get; set; }
        [Required]
        public string[]? Scopes { get; set; }
        [Required]
        public int CertId { get; set; }
        public int GroupId { get; set; }
        public string[]? RedirectUrls { get; set; }
        public int ExpiredSecond { get; set; }
        public string[]? SamlAudiences { get; set; }
        public bool SamlResponseCompress { get; set; }
        public bool SamlEncrypt { get; set; }
        public List<ProviderItem> ProviderItems { get; set; } = [];
        public Cert? Cert { get; set; }
        public Group? Group { get; set; }
        [NotMapped]
        public List<Provider> Providers { get; set; } = [];

        public Object getMaskedApplication()
        {
            return new
            {
                Id,
                Name,
                ClientId,
                Scopes,
                ProviderItems
            };
        }
    }
}
