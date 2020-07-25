using KDLib.Crypto;
using Xunit;

namespace KDLib.NET.Tests
{
  public class PasswordHasherTests
  {
    private const string TestPass = "test1";

    [Fact]
    public void TestDefault()
    {
      var hashedPassword = PasswordHasher.HashPassword(TestPass);
      Assert.True(PasswordHasher.CheckPassword(hashedPassword, TestPass));
    }

    [Fact]
    public void TestGivenSalt()
    {
      var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

      var hashedPassword = PasswordHasher.HashPassword(TestPass, iterations: 10000, hashSize: 32, salt: salt);

      Assert.True(PasswordHasher.CheckPassword(hashedPassword, TestPass));
      Assert.Equal(32, hashedPassword.Digest.Length);
      Assert.Equal(8, hashedPassword.Salt.Length);
      Assert.Equal(10000, hashedPassword.Iterations);

      var hashStr = hashedPassword.SerializeToString();

      // ReSharper disable StringLiteralTypo
      Assert.Equal("$1$10000$AQIDBAUGBwg=$u/MBH7KaW65sEUfOyscUeQwpmaAEIGWpLv05GX4iqOg=", hashStr);
      // ReSharper restore StringLiteralTypo

      Assert.True(HashedPassword.TryDeserialize(hashStr, out var hashedPasswordParsed));
      Assert.Equal(32, hashedPasswordParsed.Digest.Length);
      Assert.Equal(8, hashedPasswordParsed.Salt.Length);
      Assert.Equal(10000, hashedPasswordParsed.Iterations);
    }

    [Fact]
    public void TestTamper()
    {
      var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

      var hashedPassword = PasswordHasher.HashPassword(TestPass, salt: salt);

      Assert.True(PasswordHasher.CheckPassword(hashedPassword, TestPass));

      hashedPassword.Digest[0] += 1;

      Assert.False(PasswordHasher.CheckPassword(hashedPassword, TestPass));
    }

    [Fact]
    public void TestError()
    {
      Assert.False(HashedPassword.TryDeserialize("a.b", out _));
    }
  }
}