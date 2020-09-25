using System.Security.Cryptography;

namespace KDCryptoUtils
{
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

    public static bool CheckPassword(HashedPassword hashedPassword, string password) => hashedPassword.CheckPassword(password);
  }
}