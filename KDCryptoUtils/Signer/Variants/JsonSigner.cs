using System.Text;
using KDLib;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KDCryptoUtils.Signer
{
  public class JsonSigner : BaseSigner<object>
  {
    public JsonSigner(string key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(key, signatureLength, hashAlgorithm) { }
    public JsonSigner(byte[] key, int signatureLength = -1, HashAlgorithm hashAlgorithm = HashAlgorithm.Sha1) : base(key, signatureLength, hashAlgorithm) { }

    protected override byte[] ConvertToBytes(object value)
    {
      var jsonObject = JToken.FromObject(value);
      var normalizedObject = JsonUtils.SortKeys(jsonObject);
      var jsonString = JsonConvert.SerializeObject(normalizedObject);
      return Encoding.UTF8.GetBytes(jsonString);
    }

    protected override object ConvertFromBytes(byte[] data)
    {
      return JToken.Parse(Encoding.UTF8.GetString(data));
    }

    public T Decode<T>(string signedString, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      var rawValue = (JToken)Decode(signedString, encoding);
      return rawValue.ToObject<T>();
    }
  }
}