using System;
using System.Security.Cryptography;
using KDCryptoUtils.SignedEncrypter;
using KDCryptoUtils.Signer;
using KDLib;
using Newtonsoft.Json.Linq;
using Xunit;

namespace KDCryptoUtils.Tests
{
  public class SignedEncrypterTestsTests
  {
    private const string Key = "key1";

    [Fact]
    public void TestByte()
    {
      var encrypter = new ByteSignedEncrypter(Key, Key);

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter.Encrypt(data);
      var decryptedData = encrypter.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestString()
    {
      var encrypter = new StringSignedEncrypter(Key, Key);

      var data = "value";

      var encryptedData = encrypter.Encrypt(data);
      var decryptedData = encrypter.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestJson()
    {
      var encrypter = new JsonSignedEncrypter(Key, Key);

      var data = JToken.FromObject(new {
          a = 1,
          b = 2,
      });

      var encryptedData = encrypter.Encrypt(data);
      var decryptedData = encrypter.Decrypt<JToken>(encryptedData);

      Assert.Equal(data, decryptedData);

      var encryptedDataStr = encrypter.EncryptToString(data);
      var decryptedData2 = encrypter.DecryptFromString<JToken>(encryptedDataStr);

      Assert.Equal(data, decryptedData2);
    }

    [Fact]
    public void TestToStringDefault()
    {
      var encrypter = new StringSignedEncrypter(Key, Key);

      var data = "value";

      var encryptedDataB64 = encrypter.EncryptToString(data);
      var decryptedData = encrypter.DecryptFromString(encryptedDataB64);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestToStringB64()
    {
      var encrypter = new StringSignedEncrypter(Key, Key);

      var data = "value";

      var encryptedDataB64 = encrypter.EncryptToString(data, BinaryEncoding.Base64);
      var decryptedData = encrypter.DecryptFromString(encryptedDataB64, BinaryEncoding.Base64);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestToStringB62()
    {
      var encrypter = new StringSignedEncrypter(Key, Key);

      var data = "value";

      var encryptedDataB64 = encrypter.EncryptToString(data, BinaryEncoding.Base62);
      var decryptedData = encrypter.DecryptFromString(encryptedDataB64, BinaryEncoding.Base62);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestToStringInvalid()
    {
      var encrypter = new StringSignedEncrypter(Key, Key);

      var data = "value";

      var encryptedDataB64 = encrypter.EncryptToString(data, BinaryEncoding.Base64);

      Assert.ThrowsAny<Exception>(() => encrypter.DecryptFromString(encryptedDataB64, BinaryEncoding.Base62));

      var encryptedDataB62 = encrypter.EncryptToString(data, BinaryEncoding.Base62);

      Assert.ThrowsAny<Exception>(() => encrypter.DecryptFromString(encryptedDataB62, BinaryEncoding.Base64));
    }

    [Fact]
    public void TestDifferentKey()
    {
      var salt = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

      var encrypter1 = new ByteSignedEncrypter(Key, Key, 10000, salt);
      var encrypter2 = new ByteSignedEncrypter("kd2", "kd2");

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter1.Encrypt(data);

      Assert.Throws<BadSignatureException>(() => encrypter2.Decrypt(encryptedData));
    }

    [Fact]
    public void TestDifferentSalt()
    {
      var salt1 = new byte[] { 0, 2, 3, 4, 5, 6, 7, 8 };
      var salt2 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

      var encrypter1 = new ByteSignedEncrypter(Key, Key, 10000, salt1);
      var encrypter2 = new ByteSignedEncrypter(Key, Key, 10000, salt2);

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter1.Encrypt(data);
      var decryptedData = encrypter2.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestTamper()
    {
      var salt1 = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

      var encrypter = new ByteSignedEncrypter(Key, Key, 10000, salt1);

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter.Encrypt(data);
      encryptedData[10] = 5;

      Assert.Throws<BadSignatureException>(() => encrypter.Decrypt(encryptedData));
    }

    [Fact]
    public void TestIV()
    {
      var salt1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

      var encrypter = new ByteSignedEncrypter(Key, Key, 10000, salt1);
      encrypter.OverrideIV = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter.Encrypt(data);
      var expectedData = new byte[] {
          1, 2, 3, 4, 5, 6, 7, 8,
          19, 0,
          1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
          83, 37, 42, 60, 190, 59, 93, 85, 79, 144, 121, 190, 194, 115, 212, 249,
          174, 157, 117, 132, 83, 153, 202, 151,
      };
      Assert.Equal(expectedData, encryptedData);

      var decryptedData = encrypter.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestInvalidSalt()
    {
      Assert.Throws<ArgumentException>(() => new ByteSignedEncrypter(Key, Key, 10000, new byte[] { 0, 0, 0, 0, 0, 0, 0 }));

      Assert.Throws<ArgumentException>(() => new ByteSignedEncrypter(Key, Key, 10000, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
    }
  }
}