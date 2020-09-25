namespace KDCryptoUtils.Crypto
{
  public static class CryptoUtils
  {
    public static bool ConstantTimeAreEqual(byte[] a, byte[] b) => ConstantTimeAreEqual(a, 0, a.Length, b, 0, b.Length);

    public static bool ConstantTimeAreEqual(byte[] a, int aOffset, int aLength, byte[] b, int bOffset, int bLength)
    {
      if (aLength != bLength)
        return false;

      int cmp = 0;
      for (int i = 0; i < aLength; i++)
        cmp |= a[aOffset + i] ^ b[bOffset + i];
      return cmp == 0;
    }
  }
}