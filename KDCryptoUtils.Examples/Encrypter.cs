using System;
using KDCryptoUtils.Encrypter;
using KDLib;
using Newtonsoft.Json.Linq;

namespace KDCryptoUtils.Examples
{
  public static class Encrypter
  {
    public static void Example()
    {
      const string SecretKey = "key1";

      /********************************/
      /* Encrypt bytes                */
      /********************************/
      var bytes = new byte[] { 1, 2, 3 };
      var byteEncrypter = new ByteEncrypter(SecretKey);
      var encryptedBase64 = byteEncrypter.EncryptToString(bytes, BinaryEncoding.Base64);
      var decryptedBytes = byteEncrypter.DecryptFromString(encryptedBase64, BinaryEncoding.Base64);

      Console.WriteLine(encryptedBase64);
      Console.WriteLine($"{decryptedBytes[0]}, {decryptedBytes[1]}, {decryptedBytes[2]}");
      
      /********************************/
      /* Encrypt string               */
      /********************************/
      var str = "test";
      var stringEncrypter = new StringEncrypter(SecretKey);
      encryptedBase64 = stringEncrypter.EncryptToString(str, BinaryEncoding.Base64);
      var decryptedString = stringEncrypter.DecryptFromString(encryptedBase64, BinaryEncoding.Base64);

      Console.WriteLine(encryptedBase64);
      Console.WriteLine(decryptedString);

      /********************************/
      /* Encrypt JSON                 */
      /********************************/
      var json = JToken.FromObject(new { a = 1, b = 2 });
      var jsonEncrypter = new JsonEncrypter(SecretKey);
      encryptedBase64 = jsonEncrypter.EncryptToString(json, BinaryEncoding.Base64);
      var decryptedJSON = jsonEncrypter.DecryptFromString<JToken>(encryptedBase64, BinaryEncoding.Base64);

      Console.WriteLine(encryptedBase64);
      Console.WriteLine(decryptedJSON);
    }
  }
}