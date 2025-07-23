using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace AuthCenter.Models
{
    public class ProviderItem {
        public int? Id { get; set; }
        public string[]? Rule { get; set; }
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
        public string[]? Scopes {  get; set; }
        [Required]
        public int CertId { get; set; }
        public int GroupId { get; set; }
        public string[]? RedirectUrls { get; set; }
        public int ExpiredSecond { get; set; }
        public string[]? SamlAudiences { get; set; }
        public bool SamlResponseCompress { get; set; }
        public bool SamlEncrypt { get; set; }
        public ICollection<ProviderItem>? ProviderItems { get; set; }
        public Cert? Cert { get; set; }
        public Group? Group { get; set; }
    }
}
