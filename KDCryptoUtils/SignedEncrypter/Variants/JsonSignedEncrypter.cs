using System.Text;
using KDLib;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KDCryptoUtils.SignedEncrypter
{
  public class JsonSignedEncrypter : BaseSignedEncrypter<object>
  {
    public JsonSignedEncrypter(string encryptionKey, string signatureKey, int iterations = 10000, byte[] salt = null) : base(encryptionKey, signatureKey, iterations, salt) { }
    public JsonSignedEncrypter(byte[] encryptionKey, byte[] signatureKey, int iterations = 10000, byte[] salt = null) : base(encryptionKey, signatureKey, iterations, salt) { }

    protected override byte[] ConvertToBytes(object value)
    {
      var jsonObject = JToken.FromObject(value);
      var jsonString = JsonConvert.SerializeObject(jsonObject);
      return Encoding.UTF8.GetBytes(jsonString);
    }

    protected override object ConvertFromBytes(byte[] data)
    {
      return JToken.Parse(Encoding.UTF8.GetString(data));
    }

    public T Decrypt<T>(byte[] data)
    {
      var rawValue = (JToken)Decrypt(data);
      return rawValue.ToObject<T>();
    }

    public T DecryptFromString<T>(string data, BinaryEncoding encoding = BinaryEncoding.Base64)
    {
      var rawValue = (JToken)DecryptFromString(data, encoding);
      return rawValue.ToObject<T>();
    }
  }
}