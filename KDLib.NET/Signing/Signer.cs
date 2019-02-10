using System;
using System.Security.Cryptography;
using System.Text;

namespace KDLib.Signing
{
  public class BadSignature : Exception
  {
  }

  public class Signer
  {
    private HMACSHA1 Hmac { get; }
    private byte[] SecretKey { get; }

    public Signer(string secretKey)
    {
      SecretKey = Encoding.ASCII.GetBytes(secretKey);
      Hmac = new HMACSHA1(SecretKey);
    }

    public string GetSignatureString(byte[] value) => Convert.ToBase64String(GetSignatureBytes(value));

    public byte[] GetSignatureBytes(byte[] value) => Hmac.ComputeHash(value);

    public string Sign(byte[] value)
    {
      string valueB64 = Convert.ToBase64String(value);
      string signatureB64 = GetSignatureString(value);
      return $"{valueB64}.{signatureB64}";
    }

    public byte[] Decode(string signedString)
    {
      byte[] value;
      if (!DecodeInternal(signedString, out value))
        throw new BadSignature();
      return value;
    }

    public void ValidateSignedString(string signedString)
    {
      if (!DecodeInternal(signedString, out _))
        throw new BadSignature();
    }

    public void ValidateSignature(byte[] value, string signatureBase64) => ValidateSignature(value, Convert.FromBase64String(signatureBase64));

    public void ValidateSignature(byte[] value, byte[] signatureBytes)
    {
      if (!IsSignatureValid(value, signatureBytes))
        throw new BadSignature();
    }

    public bool IsSignedStringValid(string signedString)
    {
      return DecodeInternal(signedString, out _);
    }

    public bool IsSignatureValid(byte[] value, string signatureBase64) => IsSignatureValid(value, Convert.FromBase64String(signatureBase64));

    public bool IsSignatureValid(byte[] value, byte[] signatureBytes)
    {
      var desiredBytes = Hmac.ComputeHash(value);
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

    private bool DecodeInternal(string signedString, out byte[] value)
    {
      var parts = signedString.Split(new[] { '.' }, 2);
      if (parts.Length != 2) {
        value = null;
        return false;
      }
      else {
        string valueB64 = parts[0];
        string signature = parts[1];
        value = Convert.FromBase64String(valueB64);
        return IsSignatureValid(value, signature);
      }
    }
  }
}