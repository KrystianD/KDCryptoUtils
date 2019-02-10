using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KDLib.Signing
{
  public class JSONSigner
  {
    private readonly StringSigner _signer;

    public JSONSigner(string secretKey)
    {
      _signer = new StringSigner(secretKey);
    }

    public string Sign(object value) => Sign(JToken.FromObject(value));
    public string Sign(JToken value) => _signer.Sign(JsonToNormalizedString(value));

    public JToken Decode(string signedString)
    {
      var rawValue = _signer.Decode(signedString);
      return JToken.Parse(rawValue);
    }

    public T Decode<T>(string signedString)
    {
      var rawValue = _signer.Decode(signedString);
      return JsonConvert.DeserializeObject<T>(rawValue);
    }

    public string GetSignatureString(object value) => GetSignatureString(JToken.FromObject(value));
    public string GetSignatureString(JToken value) => _signer.GetSignatureString(JsonToNormalizedString(value));

    public byte[] GetSignatureBytes(object value) => GetSignatureBytes(JToken.FromObject(value));
    public byte[] GetSignatureBytes(JToken value) => _signer.GetSignatureBytes(JsonToNormalizedString(value));

    public void ValidateSignature(object value, string signature) => ValidateSignature(JToken.FromObject(value), signature);
    public void ValidateSignature(JToken value, string signature) => _signer.ValidateSignature(JsonToNormalizedString(value), signature);

    public bool IsSignatureValid(object value, string signature) => IsSignatureValid(JToken.FromObject(value), signature);
    public bool IsSignatureValid(JToken value, string signature) => _signer.IsSignatureValid(JsonToNormalizedString(value), signature);

    public bool IsSignatureValid(object value, byte[] signature) => IsSignatureValid(JToken.FromObject(value), signature);
    public bool IsSignatureValid(JToken value, byte[] signature) => _signer.IsSignatureValid(JsonToNormalizedString(value), signature);

    private string JsonToNormalizedString(JToken value) => JsonConvert.SerializeObject(JsonUtils.SortKeys(value));
  }
}