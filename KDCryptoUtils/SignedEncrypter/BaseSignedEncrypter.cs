using System.Linq;
using KDCryptoUtils.Encrypter;
using KDCryptoUtils.Signer;
using KDLib;

namespace KDCryptoUtils.SignedEncrypter
{
  public abstract class BaseSignedEncrypter<T>
  {
    private const int SignatureBytesLength = 8;

    private readonly ByteSigner _signer;
    private readonly ByteEncrypter _encrypter;

    public byte[] OverrideIV
    {
      get => _encrypter.OverrideIV;
      set => _encrypter.OverrideIV = value;
    }

    public BaseSignedEncrypter(string encryptionKey, string signatureKey, int iterations = 10000, byte[] salt = null)
    {
      _signer = new ByteSigner(signatureKey, SignatureBytesLength);
      _encrypter = new ByteEncrypter(encryptionKey, iterations, salt);
    }

    public BaseSignedEncrypter(byte[] encryptionKey, byte[] signatureKey, int iterations = 10000, byte[] salt = null)
    {
      _signer = new ByteSigner(signatureKey, SignatureBytesLength);
      _encrypter = new ByteEncrypter(encryptionKey, iterations, salt);
    }

    public byte[] Encrypt(T obj)
    {
      byte[] data = ConvertToBytes(obj);

      var encryptedData = _encrypter.Encrypt(data);
      var signatureBytes = _signer.GetSignatureBytes(encryptedData);

      return encryptedData.Concat(signatureBytes).ToArray();
    }

    public string EncryptToString(T obj, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      return BinaryEncoder.Encode(Encrypt(obj), encoding);
    }

    public T Decrypt(byte[] data)
    {
      var encDataLength = data.Length - SignatureBytesLength;

      _signer.ValidateSignature(data, 0, encDataLength, data, encDataLength, SignatureBytesLength);

      var decData = _encrypter.Decrypt(data, 0, encDataLength);

      return ConvertFromBytes(decData);
    }

    public T DecryptFromString(string data, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      return Decrypt(BinaryEncoder.Decode(data, encoding));
    }

    // Abstract
    protected abstract byte[] ConvertToBytes(T value);
    protected abstract T ConvertFromBytes(byte[] data);
  }
}