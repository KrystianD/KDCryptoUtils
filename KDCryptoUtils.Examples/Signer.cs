using System;
using KDCryptoUtils.HMAC;
using Newtonsoft.Json.Linq;

namespace KDCryptoUtils.Examples
{
  public static class Signer
  {
    public static void Example()
    {
      const string SecretKey = "key1";

      /********************************/
      /* Sign bytes                   */
      /********************************/
      var bytes = new byte[] { 1, 2, 3 };
      var byteEncrypter = new ByteSigner(SecretKey);
      var signedString = byteEncrypter.Sign(bytes);
      
      // validate signature
      byteEncrypter.ValidateSignedString(signedString);

      // validate signature and decode data
      var decodedBytes = byteEncrypter.Decode(signedString);
      
      Console.WriteLine($"{decodedBytes[0]}, {decodedBytes[1]}, {decodedBytes[2]}");
      
      /********************************/
      /* Sign string                  */
      /********************************/
      var str = "test";
      var stringEncrypter = new StringSigner(SecretKey);
      signedString = stringEncrypter.Sign(str);
      
      // validate signature
      stringEncrypter.ValidateSignedString(signedString);

      // validate signature and decode data
      var decodedString = stringEncrypter.Decode(signedString);
      
      Console.WriteLine(decodedString);

      /********************************/
      /* Sign JSON                    */
      /********************************/
      var json = JToken.FromObject(new { a = 1, b = 2 });
      var jsonEncrypter = new JsonSigner(SecretKey);
      signedString = jsonEncrypter.Sign(json);
      
      // validate signature
      jsonEncrypter.ValidateSignedString(signedString);

      // validate signature and decode data
      var decodedJSON = jsonEncrypter.Decode(signedString);
      
      Console.WriteLine(decodedJSON);
    }
  }
}