using AuthCenter.Models;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthCenter.Utils
{
    public class CertUtil
    {
        static public Cert CreateNewCert(string name, string cryptoAlgorithm, int cryptoSHASize, int bitSize, string type, string distinguishedName, DateTimeOffset? notAfter)
        {
            HashAlgorithmName hashAlgorithmName;
            CertificateRequest certRequest;
            var subject = new X500DistinguishedName(distinguishedName);

            switch (cryptoSHASize)
            {
                case 256: hashAlgorithmName = HashAlgorithmName.SHA256; break;
                case 384: hashAlgorithmName = HashAlgorithmName.SHA384; break;
                case 512: hashAlgorithmName = HashAlgorithmName.SHA512; break;
                default: hashAlgorithmName = HashAlgorithmName.SHA256; break;
            }
            
            switch (cryptoAlgorithm)
            {
                case "RS":
                    {
                        var algorithm = RSA.Create(keySizeInBits: bitSize);
                        certRequest = new CertificateRequest(subject, algorithm, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                        break;
                    }
                case "ES":
                    {
                        bitSize = 0;
                        var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                        certRequest = new CertificateRequest(subject, algorithm, hashAlgorithmName);
                        break;
                    }
                default:
                    {
                        var algorithm = RSA.Create(keySizeInBits: bitSize);
                        certRequest = new CertificateRequest(subject, algorithm, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                        break;
                    }
            }


            if (notAfter == null)
            {
                notAfter = DateTimeOffset.UtcNow.AddYears(10);
            }
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
            var newCert = certRequest.CreateSelfSigned(notBefore: DateTimeOffset.UtcNow, notAfter: (DateTimeOffset)notAfter);

            string? priKeyString;
            switch (cryptoAlgorithm)
            {
                case "RS":
                    {
                        priKeyString = Convert.ToBase64String(newCert.GetRSAPrivateKey()!.ExportPkcs8PrivateKey());
                        break;
                    }
                case "ES":
                    {
                        priKeyString = Convert.ToBase64String(newCert.GetECDsaPrivateKey()!.ExportPkcs8PrivateKey());
                        break;
                    }
                default:
                    {
                        priKeyString = Convert.ToBase64String(newCert.GetRSAPrivateKey()!.ExportPkcs8PrivateKey());
                        break;
                    }
            }
            var pubKeyString = Convert.ToBase64String(newCert.Export(X509ContentType.Cert));


            var cert = new Cert
            {
                Name = name,
                Type = type,
                CryptoAlgorithm = cryptoAlgorithm,
                CryptoSHASize = cryptoSHASize,
                BitSize = bitSize,
                Certificate = pubKeyString,
                PriviteKey = priKeyString,
            };

            return cert;
        }
    }
}
