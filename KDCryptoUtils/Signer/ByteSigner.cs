namespace KDCryptoUtils.Signer
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

    public new void ValidateSignature(byte[] valueBuffer, int valueOffset, int valueLength, byte[] signatureBuffer, int signatureOffset, int signatureLength)
    {
      base.ValidateSignature(valueBuffer, valueOffset, valueLength, signatureBuffer, signatureOffset, signatureLength);
    }

    public new bool IsSignatureValid(byte[] valueBuffer, int valueOffset, int valueLength, byte[] signatureBuffer, int signatureOffset, int signatureLength)
    {
      return base.IsSignatureValid(valueBuffer, valueOffset, valueLength, signatureBuffer, signatureOffset, signatureLength);
    }
  }
}