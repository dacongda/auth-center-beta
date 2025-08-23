using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.OpenSsl;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthCenter.Models
{
    [Index(nameof(Name), IsUnique = true)]
    public class Cert : BaseModel
    {
        [Required]
        public required string Name { get; set; }
        [Required]
        public required string Type { get; set; }
        [Required]
        public required int BitSize { get; set; }
        [Required]
        public required string CryptoAlgorithm { get; set; }
        [Required]
        public required int CryptoSHASize { get; set; }
        public string? Certificate { get; set; }
        public string? PriviteKey { get; set; }
        [NotMapped]
        public string? DistinguishedName { get; set; }
        [NotMapped]
        public string? Issuer { get; set; }
        [NotMapped]
        public string? Subject { get; set; }
        [NotMapped]
        public DateTime? NotAfter { get; set; }
        [NotMapped]
        public string? CertFriendlyName { get; set; }


        /**
         * 转换证书
         */
        public X509Certificate2 ToX509Certificate2()
        {

            var publicCert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Certificate ?? ""));

            if (CryptoAlgorithm == "RS")
            {
                var rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(PriviteKey ?? ""), out _);
                publicCert = publicCert.CopyWithPrivateKey(rsa);
            }
            else if (CryptoAlgorithm == "ES")
            {
                var ecdsa = ECDsa.Create();
                ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(PriviteKey ?? ""), out _);
                publicCert = publicCert.CopyWithPrivateKey(ecdsa);
            }

            return publicCert;
        }

        /**
         * 转换SK
         */
        public SecurityKey ToSecurityKey()
        {
            var x509key = ToX509Certificate2();
            if (CryptoAlgorithm == "RS")
            {
                return new X509SecurityKey(x509key);
            }
            else
            {
                var ecdsa = x509key.GetECDsaPrivateKey();
                ecdsa?.ImportSubjectPublicKeyInfo(x509key.PublicKey.ExportSubjectPublicKeyInfo(), out _);
                return new ECDsaSecurityKey(x509key.GetECDsaPrivateKey());
            }
        }

        /**
         * 转换公钥证书
         */
        public X509Certificate2 ToPulibcX509Certificate2()
        {

            var publicCert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Certificate ?? ""));
            return publicCert;
        }

        /**
         * 转换至XML格式
         */
        public string ToXmlString(bool includePrivateKey)
        {
            var publicCert = ToX509Certificate2();
            if (publicCert == null)
            {
                throw new Exception("cert transfer fail");
            }
            if (CryptoAlgorithm == "RS")
            {
                return publicCert.GetRSAPublicKey()!.ToXmlString(includePrivateKey);
            }
            else if (CryptoAlgorithm == "ES")
            {
                return publicCert.GetECDsaPrivateKey()!.ToXmlString(includePrivateKey);
            }

            throw new Exception("type not supported");
        }
    }
}
