namespace KDLib.Crypto
{
  public static class CryptoUtils
  {
    public static bool ConstantTimeAreEqual(byte[] a, byte[] b)
    {
      if (a.Length != b.Length)
        return false;

      int cmp = 0;
      for (int i = 0; i < a.Length; i++)
        cmp |= a[i] ^ b[i];
      return cmp == 0;
    }
  }
}