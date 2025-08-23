using System.Security.Cryptography;

namespace AuthCenter.Utils.ExtendCryptography
{
    public class EcdsaSignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private ECDsa key;

        public EcdsaSignatureDeformatter(ECDsa key) => this.key = key;

        public override void SetKey(AsymmetricAlgorithm key) => this.key = (key as ECDsa)!;

        public override void SetHashAlgorithm(string strName) { }

        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
            => key.VerifyHash(rgbHash, rgbSignature);
    }
}
