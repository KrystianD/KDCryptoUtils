using System;
using JetBrains.Annotations;
using KDLib;

namespace KDCryptoUtils.Signer
{
  [PublicAPI]
  public abstract partial class BaseSigner<T>
  {
    public string GetSignatureString(T value) => Convert.ToBase64String(GetSignatureBytes(value));

    public byte[] GetSignatureBytes(T value)
    {
      byte[] valueBytes = ConvertToBytes(value);
      return GetSignatureBytes(valueBytes, 0, valueBytes.Length);
    }

    public void ValidateSignedString(string signedString, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      if (!IsSignedStringValid(signedString, encoding))
        throw new BadSignatureException();
    }

    public void ValidateSignature(T value, string signatureBase64) => ValidateSignature(value, Convert.FromBase64String(signatureBase64));

    public void ValidateSignature(T value, byte[] signatureBytes)
    {
      if (!IsSignatureValid(value, signatureBytes))
        throw new BadSignatureException();
    }
    
    public void ValidateSignature(T value, byte[] signatureBuffer, int signatureOffset, int signatureLength)
    {
      if (!IsSignatureValid(value, signatureBuffer, signatureOffset, signatureLength))
        throw new BadSignatureException();
    }

    protected void ValidateSignature(byte[] valueBuffer, int valueOffset, int valueLength, byte[] signatureBuffer, int signatureOffset, int signatureLength)
    {
      if (!IsSignatureValid(valueBuffer, valueOffset, valueLength, signatureBuffer, signatureOffset, signatureLength))
        throw new BadSignatureException();
    }

    public bool IsSignedStringValid(string signedString, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      return ValidateInternal(signedString, encoding, out _);
    }

    public bool IsSignatureValid(T value, string signatureBase64) => IsSignatureValid(ConvertToBytes(value), Convert.FromBase64String(signatureBase64));

    public bool IsSignatureValid(T value, byte[] signatureBytes) => IsSignatureValid(ConvertToBytes(value), signatureBytes);

    public bool IsSignatureValid(T value, byte[] signatureBuffer, int signatureOffset, int signatureLength)
    {
      var valueBytes = ConvertToBytes(value);
      return IsSignatureValid(valueBytes, 0, valueBytes.Length, signatureBuffer, signatureOffset, signatureLength);
    }

    private bool IsSignatureValid(byte[] valueBuffer, byte[] signatureBytes)
    {
      return IsSignatureValid(valueBuffer, 0, valueBuffer.Length, signatureBytes, 0, signatureBytes.Length);
    }
  }
}