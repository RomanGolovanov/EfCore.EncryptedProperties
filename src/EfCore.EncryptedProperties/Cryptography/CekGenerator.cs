using System.Security.Cryptography;

namespace EfCore.EncryptedProperties.Cryptography;

internal static class CekGenerator
{
    private const int CekSizeBytes = 32;

    public static byte[] Generate()
    {
        return RandomNumberGenerator.GetBytes(CekSizeBytes);
    }
}
