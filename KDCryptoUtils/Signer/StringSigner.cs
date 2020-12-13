using System.Text;

namespace KDCryptoUtils.Signer
{
  public class StringSigner : BaseSigner<string>
  {
    public StringSigner(string secretKey, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(secretKey, signatureLength, hashAlgorithm) { }
    public StringSigner(byte[] secretKey, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(secretKey, signatureLength, hashAlgorithm) { }

    protected override byte[] ConvertToBytes(string value)
    {
      return Encoding.UTF8.GetBytes(value);
    }

    protected override string ConvertFromBytes(byte[] data)
    {
      return Encoding.UTF8.GetString(data);
    }
  }
}