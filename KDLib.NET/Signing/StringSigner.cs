using System.Text;

namespace KDLib.Signing
{
  public class StringSigner
  {
    private readonly Signer _signer;

    public StringSigner(string secretKey)
    {
      _signer = new Signer(secretKey);
    }

    public string Sign(string value)
    {
      return _signer.Sign(Encoding.UTF8.GetBytes(value));
    }

    public string Decode(string signedString)
    {
      var decoded = _signer.Decode(signedString);
      return Encoding.UTF8.GetString(decoded);
    }

    public void ValidateSignedString(string signedString) => _signer.ValidateSignedString(signedString);
    
    public byte[] GetSignatureBytes(string value) => _signer.GetSignatureBytes(Encoding.UTF8.GetBytes(value));

    public string GetSignatureString(string value) => _signer.GetSignatureString(Encoding.UTF8.GetBytes(value));

    public void ValidateSignature(string value, string signatureBase64)
    {
      _signer.ValidateSignature(Encoding.UTF8.GetBytes(value), signatureBase64);
    }

    public void ValidateSignature(string value, byte[] signatureBytes)
    {
      _signer.ValidateSignature(Encoding.UTF8.GetBytes(value), signatureBytes);
    }

    public bool IsSignedStringValid(string signedString) => _signer.IsSignedStringValid(signedString);

    public bool IsSignatureValid(string value, string signatureBase64) => _signer.IsSignatureValid(Encoding.UTF8.GetBytes(value), signatureBase64);
    public bool IsSignatureValid(string value, byte[] signatureBytes) => _signer.IsSignatureValid(Encoding.UTF8.GetBytes(value), signatureBytes);
  }
}