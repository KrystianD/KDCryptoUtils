using System;
using System.Security.Cryptography;
using KDCryptoUtils.Encrypter;
using KDLib;
using Newtonsoft.Json.Linq;
using Xunit;

namespace KDCryptoUtils.Tests
{
  public class EncrypterTests
  {
    private const string Key = "key1";

    [Fact]
    public void TestByte()
    {
      var encrypter = new ByteEncrypter(Key);

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter.Encrypt(data);
      var decryptedData = encrypter.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestString()
    {
      var encrypter = new StringEncrypter(Key);

      var data = "value";

      var encryptedData = encrypter.Encrypt(data);
      var decryptedData = encrypter.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestJson()
    {
      var encrypter = new JsonEncrypter(Key);

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
      var encrypter = new StringEncrypter(Key);

      var data = "value";

      var encryptedDataB64 = encrypter.EncryptToString(data);
      var decryptedData = encrypter.DecryptFromString(encryptedDataB64);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestToStringB64()
    {
      var encrypter = new StringEncrypter(Key);

      var data = "value";

      var encryptedDataB64 = encrypter.EncryptToString(data, BinaryEncoding.Base64);
      var decryptedData = encrypter.DecryptFromString(encryptedDataB64, BinaryEncoding.Base64);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestToStringB62()
    {
      var encrypter = new StringEncrypter(Key);

      var data = "value";

      var encryptedDataB64 = encrypter.EncryptToString(data, BinaryEncoding.Base62);
      var decryptedData = encrypter.DecryptFromString(encryptedDataB64, BinaryEncoding.Base62);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestToStringInvalid()
    {
      var encrypter = new StringEncrypter(Key);

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

      var encrypter1 = new ByteEncrypter(Key, 10000, salt);
      var encrypter2 = new ByteEncrypter("kd2");

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter1.Encrypt(data);

      Assert.Throws<CryptographicException>(() => encrypter2.Decrypt(encryptedData));
    }

    [Fact]
    public void TestDifferentSalt()
    {
      var salt1 = new byte[] { 0, 2, 3, 4, 5, 6, 7, 8 };
      var salt2 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

      var encrypter1 = new ByteEncrypter(Key, 10000, salt1);
      var encrypter2 = new ByteEncrypter(Key, 10000, salt2);

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter1.Encrypt(data);
      var decryptedData = encrypter2.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestIV()
    {
      var salt1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

      var encrypter = new ByteEncrypter(Key, 10000, salt1);
      encrypter.OverrideIV = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

      var data = new byte[] { 1, 2, 3 };

      var encryptedData = encrypter.Encrypt(data);
      var expectedData = new byte[] {
          1, 2, 3, 4, 5, 6, 7, 8,
          19, 0,
          1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
          83, 37, 42, 60, 190, 59, 93, 85, 79, 144, 121, 190, 194, 115, 212, 249,
      };
      Assert.Equal(expectedData, encryptedData);

      var decryptedData = encrypter.Decrypt(encryptedData);

      Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void TestInvalidSalt()
    {
      Assert.Throws<ArgumentException>(() => new ByteEncrypter(Key, 10000, new byte[] { 0, 0, 0, 0, 0, 0, 0 }));

      Assert.Throws<ArgumentException>(() => new ByteEncrypter(Key, 10000, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
    }
  }
}