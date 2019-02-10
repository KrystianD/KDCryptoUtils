using System.Diagnostics.CodeAnalysis;
using KDLib.HMAC;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace KDLib.NET.Tests
{
  [SuppressMessage("ReSharper", "StringLiteralTypo")]
  public class SignerTests
  {
    [Fact]
    public void SignBytes()
    {
      Signer s1, s2;
      string signed;
      byte[] decoded;

      s1 = new Signer("key1");

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
      var s1 = new Signer("key1");

      var signed = s1.Sign(new byte[] { 1, 2, 3 });
      signed = signed.Replace("D", "E");

      Assert.False(s1.IsSignedStringValid(signed));
      Assert.Throws<BadSignature>(() => s1.ValidateSignedString(signed));
      Assert.Throws<BadSignature>(() => s1.Decode(signed));
    }


    [Fact]
    public void Signature()
    {
      var s1 = new Signer("key1");

      var data = new byte[] { 1, 2, 3 };
      var signature = s1.GetSignatureString(data);

      Assert.True(s1.IsSignatureValid(data, signature));
    }

    [Fact]
    public void SignatureInvalid()
    {
      var s1 = new Signer("key1");

      var data = new byte[] { 1, 2, 3 };
      var signature = s1.GetSignatureString(data);
      signature = signature.Replace("D", "E");

      Assert.False(s1.IsSignatureValid(data, signature));
      Assert.Throws<BadSignature>(() => s1.ValidateSignature(data, signature));
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
      var s1 = new JSONSigner("key1");

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

      Assert.Equal(@"{""a"":1,""b"":2,""c"":{""d"":5,""a"":1}}", obj1.ToString(Formatting.None));

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

      var s1 = new JSONSigner("key1");

      var signedString = s1.Sign(obj1);

      Assert.Equal("eyJhIjoxLCJiIjoyfQ==./DNnEpUHsKFtddEVLfmig3cmLzE=", signedString);

      Assert.Equal(s1.Sign(obj1), s1.Sign(obj2));

      var decoded = s1.Decode<MyJsonObject>(signedString);

      Assert.Equal(1, decoded.Val1);
      Assert.Equal(2, decoded.Val2);
    }
  }
}