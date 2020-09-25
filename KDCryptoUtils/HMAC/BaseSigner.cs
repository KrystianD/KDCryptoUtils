using System;
using System.Security.Cryptography;
using System.Text;
using KDCryptoUtils.Crypto;
using KDLib;

namespace KDCryptoUtils.HMAC
{
  public abstract class BaseSigner<T>
  {
    private int _signatureLength;

    private HMACSHA1 Hmac { get; }
    private byte[] SecretKey { get; }

    public BaseSigner(string secretKey, int signatureLength = -1)
    {
      _signatureLength = signatureLength;

      SecretKey = Encoding.ASCII.GetBytes(secretKey);
      Hmac = new HMACSHA1(SecretKey);
    }

    public string GetSignatureString(T value) => Convert.ToBase64String(GetSignatureBytes(value));

    public byte[] GetSignatureBytes(T value)
    {
      byte[] valueBytes = ConvertToBytes(value);
      return GetSignatureBytes(valueBytes, 0, valueBytes.Length);
    }

    public byte[] GetSignatureBytes(byte[] buffer, int offset, int count)
    {
      var signatureBytes = Hmac.ComputeHash(buffer, offset, count);
      if (_signatureLength == -1) {
        return signatureBytes;
      }
      else {
        var bytesSlice = new byte[_signatureLength];
        Array.Copy(signatureBytes, bytesSlice, _signatureLength);
        return bytesSlice;
      }
    }

    public string Sign(T value, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      byte[] valueBytes = ConvertToBytes(value);
      var signatureBytes = GetSignatureBytes(valueBytes, 0, valueBytes.Length);
      return CreateSignedString(valueBytes, signatureBytes, encoding);
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

    private bool IsSignatureValid(byte[] valueBuffer, byte[] signatureBytes)
    {
      var desiredBytes = GetSignatureBytes(valueBuffer, 0, valueBuffer.Length);
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