using System;
using System.Security.Cryptography;
using System.Text;
using KDLib;

namespace KDCryptoUtils.Signer
{
  public abstract partial class BaseSigner<T>
  {
    private readonly int _signatureLength;

    private HMAC Hmac { get; }

    public BaseSigner(string key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1)
        : this(Encoding.UTF8.GetBytes(key), signatureLength, hashAlgorithm) { }

    public BaseSigner(byte[] key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1)
    {
      _signatureLength = signatureLength;

      Hmac = hashAlgorithm switch {
          HashAlgorithm.Sha1 => new HMACSHA1(key),
          HashAlgorithm.Sha256 => new HMACSHA256(key),
          HashAlgorithm.Sha384 => new HMACSHA384(key),
          HashAlgorithm.Sha512 => new HMACSHA512(key),
          _ => throw new ArgumentOutOfRangeException(nameof(hashAlgorithm), hashAlgorithm, null),
      };
    }

    protected byte[] GetSignatureBytes(byte[] buffer, int offset, int count)
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

    protected bool IsSignatureValid(byte[] valueBuffer, int valueOffset, int valueLength, byte[] signatureBuffer, int signatureOffset, int signatureLength)
    {
      var desiredBytes = GetSignatureBytes(valueBuffer, valueOffset, valueLength);
      return CryptoUtils.ConstantTimeAreEqual(desiredBytes, 0, desiredBytes.Length, signatureBuffer, signatureOffset, signatureLength);
    }

    public string Sign(T value, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      byte[] valueBytes = ConvertToBytes(value);
      var signatureBytes = GetSignatureBytes(valueBytes, 0, valueBytes.Length);
      return CreateSignedString(valueBytes, signatureBytes, encoding);
    }

    public T Decode(string signedString, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      if (!TryDecodeSignedString(signedString, encoding, out var valueBytes))
        throw new BadSignatureException();

      return ConvertFromBytes(valueBytes);
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

    private bool TryDecodeSignedString(string signedString, BinaryEncoding encoding, out byte[] valueBytes)
    {
      if (!TryParseSignedString(signedString, encoding, out valueBytes, out var signatureBytes))
        return false;

      return IsSignatureValid(valueBytes, signatureBytes);
    }

    // Abstract
    protected abstract byte[] ConvertToBytes(T value);
    protected abstract T ConvertFromBytes(byte[] data);
  }
}