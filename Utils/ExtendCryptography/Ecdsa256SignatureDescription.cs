using System.Security.Cryptography;

namespace AuthCenter.Utils.ExtendCryptography
{
    public class Ecdsa256SignatureDescription : SignatureDescription
    {
        public Ecdsa256SignatureDescription()
        {
            KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
        }

        public override HashAlgorithm CreateDigest() => SHA256.Create();

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256) throw new InvalidOperationException("Requires EC key using P-256");
            return new EcdsaSignatureFormatter(ecdsa);
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256) throw new InvalidOperationException("Requires EC key using P-256");
            return new EcdsaSignatureDeformatter(ecdsa);
        }
    }
}
