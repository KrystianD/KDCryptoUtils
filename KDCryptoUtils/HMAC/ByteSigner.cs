namespace KDCryptoUtils.HMAC
{
  public class ByteSigner : BaseSigner<byte[]>
  {
    public ByteSigner(string secretKey, int signatureLength = -1) : base(secretKey, signatureLength) { }

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