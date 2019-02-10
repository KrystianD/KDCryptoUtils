namespace KDLib.HMAC
{
  public class Signer : BaseSigner<byte[]>
  {
    public Signer(string secretKey) : base(secretKey)
    {
    }

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