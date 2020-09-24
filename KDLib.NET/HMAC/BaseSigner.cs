using System;
using System.Security.Cryptography;
using System.Text;
using KDLib.Crypto;

namespace KDLib.HMAC
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

    public string Sign(T value)
    {
      byte[] data = ConvertToBytes(value);
      string valueB64 = Convert.ToBase64String(data);
      string signatureB64 = Convert.ToBase64String(Hmac.ComputeHash(data));
      return $"{valueB64}.{signatureB64}";
    }

    public T Decode(string signedString)
    {
      if (!ValidateInternal(signedString, out var valueBytes))
        throw new BadSignatureException();

      return ConvertFromBytes(valueBytes);
    }

    public void ValidateSignedString(string signedString)
    {
      if (!IsSignedStringValid(signedString))
        throw new BadSignatureException();
    }

    public void ValidateSignature(T value, string signatureBase64) => ValidateSignature(value, Convert.FromBase64String(signatureBase64));

    public void ValidateSignature(T value, byte[] signatureBytes)
    {
      if (!IsSignatureValid(value, signatureBytes))
        throw new BadSignatureException();
    }

    public bool IsSignedStringValid(string signedString)
    {
      return ValidateInternal(signedString, out _);
    }

    public bool IsSignatureValid(T value, string signatureBase64) => IsSignatureValid(ConvertToBytes(value), Convert.FromBase64String(signatureBase64));

    public bool IsSignatureValid(T value, byte[] signatureBytes) => IsSignatureValid(ConvertToBytes(value), signatureBytes);

    private bool IsSignatureValid(byte[] data, byte[] signatureBytes)
    {
      var desiredBytes = Hmac.ComputeHash(data);
      return CryptoUtils.ConstantTimeAreEqual(desiredBytes, signatureBytes);
    }

    // Helpers
    private bool ValidateInternal(string signedString, out byte[] valueBytes)
    {
      if (!TryParseSignedString(signedString, out valueBytes, out var signatureBytes))
        return false;

      return IsSignatureValid(valueBytes, signatureBytes);
    }

    private static bool TryParseSignedString(string signedString, out byte[] valueBytes, out byte[] signatureBytes)
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
        valueBytes = Convert.FromBase64String(valueB64);
        signatureBytes = Convert.FromBase64String(signatureB64);
        return true;
      }
    }

    // Abstract
    protected abstract byte[] ConvertToBytes(T value);
    protected abstract T ConvertFromBytes(byte[] data);
  }
}