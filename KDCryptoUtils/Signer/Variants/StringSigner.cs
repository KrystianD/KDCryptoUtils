using System.Text;

namespace KDCryptoUtils.Signer
{
  public class StringSigner : BaseSigner<string>
  {
    public StringSigner(string key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(key, signatureLength, hashAlgorithm) { }
    public StringSigner(byte[] key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(key, signatureLength, hashAlgorithm) { }

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