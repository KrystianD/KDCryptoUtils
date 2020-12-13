using System.Diagnostics.CodeAnalysis;
using KDCryptoUtils.Signer;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace KDCryptoUtils.Tests
{
  [SuppressMessage("ReSharper", "StringLiteralTypo")]
  public class SignerTests
  {
    [Fact]
    public void SignBytes()
    {
      string signed;
      byte[] decoded;

      var s1 = new ByteSigner("key1");

      signed = s1.Sign(new byte[] { 1, 2, 3 });
      Assert.Equal("AQID.1DmDykkgnOXtgssgfJYjDF7ANKk=", signed);

      signed = s1.Sign(new byte[] { 1, 2, 4 });
      Assert.Equal("AQIE.hMzmM4WyYiVOV2JtCBNmbxT0LPs=", signed);

      decoded = s1.Decode(signed);
      Assert.Equal(new byte[] { 1, 2, 4 }, decoded);

      Assert.True(s1.IsSignedStringValid(signed));
    }

    [Fact]
    public void SignBytesInvalid()
    {
      var s1 = new ByteSigner("key1");

      var signed = s1.Sign(new byte[] { 1, 2, 3 });
      signed = signed.Replace("D", "E");

      Assert.False(s1.IsSignedStringValid(signed));
      Assert.Throws<BadSignatureException>(() => s1.ValidateSignedString(signed));
      Assert.Throws<BadSignatureException>(() => s1.Decode(signed));
    }

    [Fact]
    public void Signature()
    {
      var s1 = new ByteSigner("key1");

      var data = new byte[] { 1, 2, 3 };
      var signatureString = s1.GetSignatureString(data);
      var signatureBytes = s1.GetSignatureBytes(data);

      Assert.True(s1.IsSignatureValid(data, signatureString));
      Assert.Null(Record.Exception(() => s1.ValidateSignature(data, signatureString)));
      
      Assert.True(s1.IsSignatureValid(data, signatureBytes));
      Assert.True(s1.IsSignatureValid(data, 0, data.Length, signatureBytes, 0, signatureBytes.Length));
      Assert.Null(Record.Exception(() => s1.ValidateSignature(data, signatureBytes)));
      Assert.Null(Record.Exception(() => s1.ValidateSignature(data, signatureBytes, 0, signatureBytes.Length)));
    }

    [Fact]
    public void SignatureInvalid()
    {
      var s1 = new ByteSigner("key1");

      var data = new byte[] { 1, 2, 3 };
      var signatureString = s1.GetSignatureString(data);
      signatureString = signatureString.Replace("D", "E");
      
      var signatureBytes = s1.GetSignatureBytes(data);
      signatureBytes[2] = 1;

      Assert.False(s1.IsSignatureValid(data, signatureString));
      Assert.Throws<BadSignatureException>(() => s1.ValidateSignature(data, signatureString));

      Assert.False(s1.IsSignatureValid(data, signatureBytes));
      Assert.False(s1.IsSignatureValid(data, 0, data.Length, signatureBytes, 0, signatureBytes.Length));
      Assert.Throws<BadSignatureException>(() => s1.ValidateSignature(data, signatureBytes));
      Assert.Throws<BadSignatureException>(() => s1.ValidateSignature(data, signatureBytes, 0, signatureBytes.Length));
    }

    [Fact]
    public void SignedString()
    {
      var s1 = new ByteSigner("key1");

      var signedString = "AQIE.hMzmM4WyYiVOV2JtCBNmbxT0LPs=";

      Assert.Null(Record.Exception(() => s1.ValidateSignedString(signedString)));
    }

    [Fact]
    public void SignedStringInvalid()
    {
      var s1 = new ByteSigner("key1");

      var signedString = "AQIE.hMzmM4WyYiVOV2JtCBNmbxT0LPs=";

      signedString = signedString.Replace(".", "_");

      Assert.False(s1.IsSignedStringValid(signedString));
    }

    [Fact]
    public void SignString()
    {
      var s1 = new StringSigner("key1");
      var signature = s1.GetSignatureString("A");
      var signedString = s1.Sign("A");

      Assert.Equal("D6j8Lb/OdwcjGjr/musc/MGN0gs=", signature);
      Assert.Equal("QQ==.D6j8Lb/OdwcjGjr/musc/MGN0gs=", signedString);

      Assert.Equal("A", s1.Decode(signedString));
    }

    [Fact]
    public void SignJson()
    {
      var s1 = new JsonSigner("key1");

      var obj1 = JToken.FromObject(new {
          a = 1,
          b = 2,
          c = new {
              d = 5,
              a = 1,
          },
      });

      Assert.Equal(@"{""a"":1,""b"":2,""c"":{""d"":5,""a"":1}}", obj1.ToString(Formatting.None));

      var obj2 = JToken.FromObject(new { // the same values as obj1, different order
          c = new {
              d = 5,
              a = 1,
          },
          b = 2,
          a = 1,
      });

      Assert.Equal(@"{""c"":{""d"":5,""a"":1},""b"":2,""a"":1}", obj2.ToString(Formatting.None));

      var signedString = s1.Sign(obj1);

      Assert.Equal("eyJhIjoxLCJiIjoyLCJjIjp7ImEiOjEsImQiOjV9fQ==.RHngY7sw47+PQ0P20W4+dNmPKV8=", signedString);

      Assert.Equal(s1.Sign(obj1), s1.Sign(obj2));
    }

    public class MyJsonObject
    {
      [JsonProperty("a")]
      public int Val1;

      [JsonProperty("b")]
      public int Val2;
    }

    [Fact]
    public void SignJsonObject()
    {
      var obj1 = new MyJsonObject() { Val1 = 1, Val2 = 2 };
      var obj2 = new MyJsonObject() { Val1 = 1, Val2 = 2 };

      var s1 = new JsonSigner("key1");

      var signedString = s1.Sign(obj1);

      Assert.Equal("eyJhIjoxLCJiIjoyfQ==./DNnEpUHsKFtddEVLfmig3cmLzE=", signedString);

      Assert.Equal(s1.Sign(obj1), s1.Sign(obj2));

      var decoded = s1.Decode<MyJsonObject>(signedString);

      Assert.Equal(1, decoded.Val1);
      Assert.Equal(2, decoded.Val2);
    }
  }
}