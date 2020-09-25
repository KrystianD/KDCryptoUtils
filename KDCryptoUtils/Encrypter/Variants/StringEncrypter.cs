using System.Text;

namespace KDCryptoUtils.Encrypter
{
  public class StringEncrypter : BaseEncrypter<string>
  {
    public StringEncrypter(string key, int iterations = 10000, byte[] salt = null) : base(key, iterations, salt) { }
    public StringEncrypter(byte[] key, int iterations = 10000, byte[] salt = null) : base(key, iterations, salt) { }

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