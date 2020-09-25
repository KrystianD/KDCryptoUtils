namespace KDCryptoUtils.HMAC
{
  public class ByteSigner : BaseSigner<byte[]>
  {
    public ByteSigner(string secretKey) : base(secretKey) { }

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