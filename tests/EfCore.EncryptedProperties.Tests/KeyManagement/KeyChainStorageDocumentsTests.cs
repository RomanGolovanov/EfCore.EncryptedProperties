using System.Text;
using EfCore.EncryptedProperties.KeyManagement;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public sealed class KeyChainStorageDocumentsTests
{
    [Fact]
    public void Read_NullJson_ThrowsFormatException()
    {
        var ex = Assert.Throws<FormatException>(() =>
            Read("null"));

        Assert.Contains("empty or invalid", ex.Message);
    }

    [Fact]
    public void Read_MalformedJson_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Read("{"));
    }

    [Fact]
    public void Read_UnsupportedFormatVersion_Throws()
    {
        var ex = Assert.Throws<FormatException>(() =>
            Read("""
                {
                  "formatVersion": 2,
                  "purpose": "default",
                  "keys": []
                }
                """));

        Assert.Contains("unsupported format version", ex.Message);
    }

    [Fact]
    public void Read_MissingPurpose_Throws()
    {
        var ex = Assert.Throws<FormatException>(() =>
            Read("""
                {
                  "formatVersion": 1,
                  "purpose": " ",
                  "keys": []
                }
                """));

        Assert.Contains("missing purpose", ex.Message);
    }

    [Fact]
    public void Read_MissingKeys_Throws()
    {
        var ex = Assert.Throws<FormatException>(() =>
            Read("""
                {
                  "formatVersion": 1,
                  "purpose": "default",
                  "keys": null
                }
                """));

        Assert.Contains("missing keys collection", ex.Message);
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000", "rsa-key", "A256GCMKW", "wrapped", "empty ID")]
    [InlineData("11111111-1111-1111-1111-111111111111", " ", "A256GCMKW", "wrapped", "missing RSA key ID")]
    [InlineData("11111111-1111-1111-1111-111111111111", "rsa-key", " ", "wrapped", "missing algorithm")]
    [InlineData("11111111-1111-1111-1111-111111111111", "rsa-key", "A256GCMKW", " ", "missing encrypted key")]
    public void Read_InvalidKeyFields_Throw(
        string id,
        string rsaKeyId,
        string algorithm,
        string encryptedKey,
        string expectedMessage)
    {
        var ex = Assert.Throws<FormatException>(() =>
            Read($$"""
                {
                  "formatVersion": 1,
                  "purpose": "default",
                  "keys": [
                    {
                      "id": "{{id}}",
                      "rsaKeyId": "{{rsaKeyId}}",
                      "algorithm": "{{algorithm}}",
                      "encryptedKey": "{{encryptedKey}}",
                      "createdAt": "2026-01-01T00:00:00+00:00",
                      "isActive": true
                    }
                  ]
                }
                """));

        Assert.Contains(expectedMessage, ex.Message);
    }

    [Fact]
    public void ValidateCandidate_WhenPurposeDiffers_Throws()
    {
        var record = CreateRecord("actual", isActive: true);

        Assert.Throws<ArgumentException>(() =>
            KeyChainStorageDocuments.ValidateCandidate("expected", record));
    }

    [Fact]
    public void ValidateCandidate_WhenCandidateInactive_Throws()
    {
        var record = CreateRecord("default", isActive: false);

        var ex = Assert.Throws<ArgumentException>(() =>
            KeyChainStorageDocuments.ValidateCandidate("default", record));

        Assert.Contains("must be active", ex.Message);
    }

    [Fact]
    public void ComputePurposeHash_IsStableSha256Hex()
    {
        var hash = KeyChainStorageDocuments.ComputePurposeHash("email");

        Assert.Equal("82244417f956ac7c599f191593f7e441a4fafa20a4158fd52e154f1dc4c8ed92", hash);
    }

    private static KeyChainDocument Read(string json)
        => KeyChainStorageDocuments.Read(Encoding.UTF8.GetBytes(json), "test.json");

    private static EncryptedKeyRecord CreateRecord(string purpose, bool isActive)
    {
        return new EncryptedKeyRecord
        {
            Id = Guid.NewGuid(),
            Purpose = purpose,
            RsaKeyId = "rsa-key",
            Algorithm = "A256GCMKW",
            EncryptedKey = "wrapped",
            CreatedAt = DateTimeOffset.UtcNow,
            IsActive = isActive
        };
    }
}
