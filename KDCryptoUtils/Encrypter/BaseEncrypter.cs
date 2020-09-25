using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KDLib;

namespace KDCryptoUtils.Encrypter
{
  public abstract class BaseEncrypter<T>
  {
    private const int SaltLength = 8;
    private const int IterationsDivider = 512;

    private readonly byte[] _key;
    private readonly int _iterations;
    private readonly byte[] _salt;
    private readonly byte[] _derivedKey;

    public byte[] OverrideIV { get; set; } = null;

    public BaseEncrypter(string key, int iterations = 10000, byte[] salt = null)
        : this(Encoding.UTF8.GetBytes(key), iterations, salt) { }

    public BaseEncrypter(byte[] key, int iterations = 10000, byte[] salt = null)
    {
      salt ??= CryptoUtils.GetCryptoRandomBytes(SaltLength);

      if (salt.Length != SaltLength)
        throw new ArgumentException("Salt must be null or 8-byte array");

      _salt = salt;
      _iterations = (iterations / IterationsDivider) * IterationsDivider;
      _key = key;
      _derivedKey = DeriveKey(key, 32, _salt, _iterations);
    }

    public byte[] Encrypt(T obj)
    {
      byte[] data = ConvertToBytes(obj);

      using var rijndael = new RijndaelManaged { Key = _derivedKey };

      if (OverrideIV == null)
        rijndael.GenerateIV();
      else
        rijndael.IV = OverrideIV;

      using var encryptor = rijndael.CreateEncryptor();
      using var msEncrypt = new MemoryStream();

      using (var bw = new BinaryWriter(msEncrypt, Encoding.Default, true)) {
        bw.Write(_salt);
        bw.Write((ushort)(_iterations / IterationsDivider));
        bw.Write(rijndael.IV);
      }

      using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)) {
        csEncrypt.Write(data, 0, data.Length);
      }

      return msEncrypt.ToArray();
    }

    public string EncryptToString(T obj, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      return BinaryEncoder.Encode(Encrypt(obj), encoding);
    }

    public T Decrypt(byte[] data, int offset, int length)
    {
      using var rijndael = new RijndaelManaged();
      using var msEncrypted = new MemoryStream(data);
      msEncrypted.Position = offset;
      msEncrypted.SetLength(offset + length);

      using (var br = new BinaryReader(msEncrypted, Encoding.Default, true)) {
        var salt = br.ReadBytes(SaltLength);
        var iterations = br.ReadUInt16() * IterationsDivider;
        var iv = br.ReadBytes(rijndael.BlockSize / 8);

        rijndael.Key = DeriveKey(_key, 32, salt, iterations);
        rijndael.IV = iv;
      }

      using (var msDecrypted = new MemoryStream(data.Length))
      using (var decryptor = rijndael.CreateDecryptor()) {
        using (var csDecrypt = new CryptoStream(msEncrypted, decryptor, CryptoStreamMode.Read)) {
          csDecrypt.CopyTo(msDecrypted);
        }

        var decryptedData = msDecrypted.ToArray();

        return ConvertFromBytes(decryptedData);
      }
    }

    public T Decrypt(byte[] data) => Decrypt(data, 0, data.Length);

    public T DecryptFromString(string data, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      return Decrypt(BinaryEncoder.Decode(data, encoding));
    }

    private static byte[] DeriveKey(byte[] key, int keyLength, byte[] salt, int iterations)
    {
      using var derived = new Rfc2898DeriveBytes(key, salt, iterations);

      return derived.GetBytes(keyLength);
    }

    // Abstract
    protected abstract byte[] ConvertToBytes(T value);
    protected abstract T ConvertFromBytes(byte[] data);
  }
}