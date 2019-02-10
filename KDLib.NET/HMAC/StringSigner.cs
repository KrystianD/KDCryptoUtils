using System.Text;

namespace KDLib.HMAC
{
  public class StringSigner : BaseSigner<string>
  {
    public StringSigner(string secretKey) : base(secretKey)
    {
    }

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