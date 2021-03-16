namespace KDCryptoUtils.SignedEncrypter
{
  public class ByteSignedEncrypter : BaseSignedEncrypter<byte[]>
  {
    public ByteSignedEncrypter(string encryptionKey, string signatureKey, int iterations = 10000, byte[] salt = null) : base(encryptionKey, signatureKey, iterations, salt) { }
    public ByteSignedEncrypter(byte[] encryptionKey, byte[] signatureKey, int iterations = 10000, byte[] salt = null) : base(encryptionKey, signatureKey, iterations, salt) { }

    protected override byte[] ConvertToBytes(byte[] value)
    {
      return value;
    }

    protected override byte[] ConvertFromBytes(byte[] data)
    {
      return data;
    }
  }
}