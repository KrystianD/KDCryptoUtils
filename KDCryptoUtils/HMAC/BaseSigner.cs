using System;
using System.Security.Cryptography;
using System.Text;
using KDCryptoUtils.Crypto;
using KDLib;

namespace KDCryptoUtils.HMAC
{
  public abstract class BaseSigner<T>
  {
    private HMACSHA1 Hmac { get; }
    private byte[] SecretKey { get; }

    public BaseSigner(string secretKey)
    {
      SecretKey = Encoding.ASCII.GetBytes(secretKey);
      Hmac = new HMACSHA1(SecretKey);
    }

    public string GetSignatureString(T value) => Convert.ToBase64String(GetSignatureBytes(value));

    public byte[] GetSignatureBytes(T value) => Hmac.ComputeHash(ConvertToBytes(value));

    public byte[] GetSignatureBytes(byte[] buffer, int offset, int count) => Hmac.ComputeHash(buffer, offset, count);

    public string Sign(T value, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      byte[] data = ConvertToBytes(value);
      return CreateSignedString(data, Hmac.ComputeHash(data), encoding);
    }

    public T Decode(string signedString, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      if (!ValidateInternal(signedString, encoding, out var valueBytes))
        throw new BadSignatureException();

      return ConvertFromBytes(valueBytes);
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

    public bool IsSignedStringValid(string signedString, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      return ValidateInternal(signedString, encoding, out _);
    }

    public bool IsSignatureValid(T value, string signatureBase64) => IsSignatureValid(ConvertToBytes(value), Convert.FromBase64String(signatureBase64));

    public bool IsSignatureValid(T value, byte[] signatureBytes) => IsSignatureValid(ConvertToBytes(value), signatureBytes);

    private bool IsSignatureValid(byte[] data, byte[] signatureBytes)
    {
      var desiredBytes = Hmac.ComputeHash(data);
      return CryptoUtils.ConstantTimeAreEqual(desiredBytes, signatureBytes);
    }

    // Helpers
    private bool ValidateInternal(string signedString, BinaryEncoding encoding, out byte[] valueBytes)
    {
      if (!TryParseSignedString(signedString, encoding, out valueBytes, out var signatureBytes))
        return false;

      return IsSignatureValid(valueBytes, signatureBytes);
    }

    private static string CreateSignedString(byte[] valueBytes, byte[] signatureBytes, BinaryEncoding encoding)
    {
      string valueB64 = BinaryEncoder.Encode(valueBytes, encoding);
      string signatureB64 = BinaryEncoder.Encode(signatureBytes, encoding);
      return $"{valueB64}.{signatureB64}";
    }

    private static bool TryParseSignedString(string signedString, BinaryEncoding encoding, out byte[] valueBytes, out byte[] signatureBytes)
    {
      var parts = signedString.Split(new[] { '.' }, 2);
      if (parts.Length != 2) {
        valueBytes = default;
        signatureBytes = default;
        return false;
      }
      else {
        string valueB64 = parts[0];
        string signatureB64 = parts[1];
        valueBytes = BinaryEncoder.Decode(valueB64, encoding);
        signatureBytes = BinaryEncoder.Decode(signatureB64, encoding);
        return true;
      }
    }

    // Abstract
    protected abstract byte[] ConvertToBytes(T value);
    protected abstract T ConvertFromBytes(byte[] data);
  }
}