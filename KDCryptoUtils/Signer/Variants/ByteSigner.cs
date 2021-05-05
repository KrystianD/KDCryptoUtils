namespace KDCryptoUtils.Signer
{
  public class ByteSigner : BaseSigner<byte[]>
  {
    public ByteSigner(string key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(key, signatureLength, hashAlgorithm) { }
    public ByteSigner(byte[] key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(key, signatureLength, hashAlgorithm) { }

    protected override byte[] ConvertToBytes(byte[] value)
    {
      return value;
    }

    protected override byte[] ConvertFromBytes(byte[] data)
    {
      return data;
    }

    public new byte[] GetSignatureBytes(byte[] buffer, int offset, int count)
    {
      return base.GetSignatureBytes(buffer, offset, count);
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