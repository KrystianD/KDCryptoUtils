using System.Text;

namespace KDCryptoUtils.SignedEncrypter
{
  public class StringSignedEncrypter : BaseSignedEncrypter<string>
  {
    public StringSignedEncrypter(string encryptionKey, string signatureKey, int iterations = 10000, byte[] salt = null) : base(encryptionKey, signatureKey, iterations, salt) { }
    public StringSignedEncrypter(byte[] encryptionKey, byte[] signatureKey, int iterations = 10000, byte[] salt = null) : base(encryptionKey, signatureKey, iterations, salt) { }

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