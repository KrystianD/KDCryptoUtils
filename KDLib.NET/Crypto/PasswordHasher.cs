using System;
using System.Security.Cryptography;

namespace KDLib.Crypto
{
  public class HashedPassword
  {
    public enum HashTypeEnum
    {
      Sha1 = 1,
    }

    public HashTypeEnum HashType;
    public int Iterations;
    public byte[] Salt;
    public byte[] Digest;

    public string SerializeToString()
    {
      // ReSharper disable once UseStringInterpolation
      return string.Format("${0}${1}${2}${3}", (int) HashType, Iterations, Convert.ToBase64String(Salt), Convert.ToBase64String(Digest));
    }

    public static bool TryDeserialize(string serialized, out HashedPassword hashedPassword)
    {
      hashedPassword = new HashedPassword();

      var parts = serialized.Split('$');

      if (parts.Length != 5 ||
          !int.TryParse(parts[1], out var hashTypeInt) ||
          !int.TryParse(parts[2], out hashedPassword.Iterations))
        return false;

      hashedPassword.HashType = (HashTypeEnum) hashTypeInt;
      hashedPassword.Salt = Convert.FromBase64String(parts[3]);
      hashedPassword.Digest = Convert.FromBase64String(parts[4]);
      return true;
    }
  }

  public static class PasswordHasher
  {
    public static HashedPassword HashPassword(string password, int iterations = 10000, int hashSize = 32, byte[] salt = null)
    {
      using (var derived = salt == null ? new Rfc2898DeriveBytes(password, 8, iterations) : new Rfc2898DeriveBytes(password, salt, iterations)) {
        return new HashedPassword() {
            HashType = HashedPassword.HashTypeEnum.Sha1,
            Iterations = iterations,
            Salt = derived.Salt,
            Digest = derived.GetBytes(hashSize),
        };
      }
    }

    public static bool CheckPassword(HashedPassword hashedPassword, string password)
    {
      using (var derived = new Rfc2898DeriveBytes(password, hashedPassword.Salt, hashedPassword.Iterations)) {
        var digest = derived.GetBytes(hashedPassword.Digest.Length);

        return CryptoUtils.ConstantTimeAreEqual(digest, hashedPassword.Digest);
      }
    }
  }
}