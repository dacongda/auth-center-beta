using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace AuthCenter.Models
{
    public class UserInfoMap
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string PreferredName { get; set; } = "";
        public string Email { get; set; } = "";
        public string Phone { get; set; } = "";
    }

    [Index(nameof(Name), IsUnique = true)]
    public class Provider : BaseModel
    {
        [Required]
        public required string Name { get; set; }
        public string DisplayName { get; set; } = "";
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

        public string? AuthEndpoint { get; set; }
        public string? TokenEndpoint { get; set; }
        public string? UserInfoEndpoint { get; set; }
        public string? JwksEndpoint { get; set; }
        public string? Scopes { get; set; }
        public string? TokenType { get; set; }

        public UserInfoMap? UserInfoMap { get; set; }
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
        public string? LinkBody { get; set; }
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
