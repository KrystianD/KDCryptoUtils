namespace KDCryptoUtils.Encrypter
{
  public class ByteEncrypter : BaseEncrypter<byte[]>
  {
    public ByteEncrypter(string key, int iterations = 10000, byte[] salt = null) : base(key, iterations, salt) { }
    public ByteEncrypter(byte[] key, int iterations = 10000, byte[] salt = null) : base(key, iterations, salt) { }

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