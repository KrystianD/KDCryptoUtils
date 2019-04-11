using System;
using System.Security.Cryptography;
using System.Text;

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
      T value;
      if (!DecodeInternal(signedString, out value))
        throw new BadSignatureException();
      return value;
    }

    public void ValidateSignedString(string signedString)
    {
      if (!DecodeInternal(signedString, out _))
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
      return DecodeInternal(signedString, out _);
    }

    public bool IsSignatureValid(T value, string signatureBase64) => IsSignatureValid(value, Convert.FromBase64String(signatureBase64));

    public bool IsSignatureValid(T value, byte[] signatureBytes)
    {
      var desiredBytes = Hmac.ComputeHash(ConvertToBytes(value));
      return ConstantTimeAreEqual(desiredBytes, signatureBytes);
    }

    // Helpers
    private static bool ConstantTimeAreEqual(byte[] a, byte[] b)
    {
      if (a.Length != b.Length)
        return false;

      int cmp = 0;
      for (int i = 0; i < a.Length; i++)
        cmp |= a[i] ^ b[i];
      return cmp == 0;
    }

    private bool DecodeInternal(string signedString, out T value)
    {
      var parts = signedString.Split(new[] { '.' }, 2);
      if (parts.Length != 2) {
        value = default;
        return false;
      }
      else {
        string valueB64 = parts[0];
        string signature = parts[1];
        value = ConvertFromBytes(Convert.FromBase64String(valueB64));
        return IsSignatureValid(value, signature);
      }
    }

    // Abstract
    protected abstract byte[] ConvertToBytes(T value);
    protected abstract T ConvertFromBytes(byte[] data);
  }
}