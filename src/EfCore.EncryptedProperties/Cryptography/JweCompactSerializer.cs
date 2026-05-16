using System.Text;

namespace EfCore.EncryptedProperties.Cryptography;

internal static class JweCompactSerializer
{
    public static string Serialize(JweHeader header, byte[] wrappedCek, byte[] iv, byte[] ciphertext, byte[] tag)
    {
        var headerB64 = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJson()));
        var encKeyB64 = Base64Url.Encode(wrappedCek);
        var ivB64 = Base64Url.Encode(iv);
        var ciphertextB64 = Base64Url.Encode(ciphertext);
        var tagB64 = Base64Url.Encode(tag);
        return $"{headerB64}.{encKeyB64}.{ivB64}.{ciphertextB64}.{tagB64}";
    }

    public static JweComponents Deserialize(string compact)
    {
        var parts = compact.Split('.');
        if (parts.Length != 5)
            throw new FormatException("Invalid JWE compact serialization: expected 5 parts.");

        var headerJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[0]));
        var header = JweHeader.FromJson(headerJson);

        return new JweComponents
        {
            RawHeaderB64 = parts[0],
            Header = header,
            WrappedCek = Base64Url.Decode(parts[1]),
            Iv = Base64Url.Decode(parts[2]),
            Ciphertext = Base64Url.Decode(parts[3]),
            Tag = Base64Url.Decode(parts[4])
        };
    }
}

internal sealed class JweComponents
{
    public required string RawHeaderB64 { get; init; }
    public required JweHeader Header { get; init; }
    public required byte[] WrappedCek { get; init; }
    public required byte[] Iv { get; init; }
    public required byte[] Ciphertext { get; init; }
    public required byte[] Tag { get; init; }
}
