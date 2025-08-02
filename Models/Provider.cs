using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthCenter.Models
{
    [Index(nameof(Name), IsUnique = true)]
    public class Provider : BaseModel
    {
        [Required]
        public required string Name { get; set; }
        [Required]
        public required string Type { get; set; }
        [Required]
        public required string SubType { get; set; }
        public string? FaviconUrl { get; set; }
        /**
         * ClientId for OAuth Username for Email
         */
        public string? ClientId { get; set; }
        /**
         * ClientSecret for OAuth Password for Email
         */
        public string? ClientSecret { get; set; }
        public int? CertId { get; set; }
        /**
         * Metadata Url for SAML, 
         * Openid-configure for OIDC, 
         * SMTP server for Email
         * Endpoint for S3
         */
        public string? ConfigureUrl { get; set; }
        /**
         * Subject for Email
         * Bucket for S3
         */
        public string? Subject { get; set; }
        /**
         * Body for Email
         * Path Prefix for S3
         */
        public string? Body { get; set; }
        public bool? EnableSSL { get; set; }
        /**
         * code length for default captcha
         */
        public int? Port { get; set; }
        /**
         * For S3 OSS
         */
        public string? RegionId { get; set; }
        public string? Domain { get; set; }
    }
}
