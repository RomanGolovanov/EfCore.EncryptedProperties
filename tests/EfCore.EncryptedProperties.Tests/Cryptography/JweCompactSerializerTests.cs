using EfCore.EncryptedProperties.Cryptography;

namespace EfCore.EncryptedProperties.Tests.Cryptography;

public class JweCompactSerializerTests
{
    [Fact]
    public void Serialize_Deserialize_RoundTrip()
    {
        var header = new JweHeader
        {
            Alg = "A256GCMKW",
            Enc = "A256GCM",
            Kid = "test-key-id",
            Iv = Base64Url.Encode(new byte[12]),
            Tag = Base64Url.Encode(new byte[16])
        };
        var wrappedCek = new byte[] { 1, 2, 3, 4, 5 };
        var iv = new byte[] { 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
        var ciphertext = new byte[] { 18, 19, 20 };
        var tag = new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 };

        var compact = JweCompactSerializer.Serialize(header, wrappedCek, iv, ciphertext, tag);
        var components = JweCompactSerializer.Deserialize(compact);

        Assert.Equal("A256GCMKW", components.Header.Alg);
        Assert.Equal("A256GCM", components.Header.Enc);
        Assert.Equal("test-key-id", components.Header.Kid);
        Assert.Equal(wrappedCek, components.WrappedCek);
        Assert.Equal(iv, components.Iv);
        Assert.Equal(ciphertext, components.Ciphertext);
        Assert.Equal(tag, components.Tag);
    }

    [Fact]
    public void Serialize_ProducesFiveParts()
    {
        var header = new JweHeader
        {
            Alg = "A256GCMKW",
            Enc = "A256GCM",
            Kid = "kid"
        };

        var compact = JweCompactSerializer.Serialize(header, [1], [2], [3], [4]);
        var parts = compact.Split('.');

        Assert.Equal(5, parts.Length);
    }

    [Fact]
    public void Deserialize_InvalidFormat_Throws()
    {
        Assert.Throws<FormatException>(() =>
            JweCompactSerializer.Deserialize("only.three.parts"));
    }

    [Fact]
    public void Deserialize_PreservesRawHeaderB64()
    {
        var header = new JweHeader
        {
            Alg = "A256GCMKW",
            Enc = "A256GCM",
            Kid = "kid"
        };

        var compact = JweCompactSerializer.Serialize(header, [1], [2], [3], [4]);
        var components = JweCompactSerializer.Deserialize(compact);

        Assert.Equal(compact.Split('.')[0], components.RawHeaderB64);
    }
}
