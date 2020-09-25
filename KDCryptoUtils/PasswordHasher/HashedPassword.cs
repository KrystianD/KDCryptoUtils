using System;
using System.Security.Cryptography;

namespace KDCryptoUtils
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
      return string.Format("${0}${1}${2}${3}", (int)HashType, Iterations, Convert.ToBase64String(Salt), Convert.ToBase64String(Digest));
    }

    public static bool TryDeserialize(string serialized, out HashedPassword hashedPassword)
    {
      hashedPassword = new HashedPassword();

      var parts = serialized.Split('$');

      if (parts.Length != 5 ||
          !int.TryParse(parts[1], out var hashTypeInt) ||
          !int.TryParse(parts[2], out hashedPassword.Iterations))
        return false;

      hashedPassword.HashType = (HashTypeEnum)hashTypeInt;
      hashedPassword.Salt = Convert.FromBase64String(parts[3]);
      hashedPassword.Digest = Convert.FromBase64String(parts[4]);
      return true;
    }

    public bool CheckPassword(string password)
    {
      using (var derived = new Rfc2898DeriveBytes(password, Salt, Iterations)) {
        var digest = derived.GetBytes(Digest.Length);

        return CryptoUtils.ConstantTimeAreEqual(digest, Digest);
      }
    }
  }
}