using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EfCore.EncryptedProperties.KeyManagement;

internal static class KeyChainStorageDocuments
{
    private const int CurrentFormatVersion = 1;

    public static async ValueTask<KeyChainDocument> ReadAsync(
        Stream stream,
        string source,
        CancellationToken cancellationToken)
    {
        var document = await JsonSerializer.DeserializeAsync(
            stream,
            KeyChainStorageJsonContext.Default.KeyChainDocument,
            cancellationToken);

        if (document is null)
            throw new FormatException($"Key chain document '{source}' is empty or invalid.");

        Validate(source, document);
        return document;
    }

    public static KeyChainDocument Read(
        ReadOnlySpan<byte> utf8Json,
        string source)
    {
        var document = JsonSerializer.Deserialize(
            utf8Json,
            KeyChainStorageJsonContext.Default.KeyChainDocument);

        if (document is null)
            throw new FormatException($"Key chain document '{source}' is empty or invalid.");

        Validate(source, document);
        return document;
    }

    public static async ValueTask WriteAsync(
        Stream stream,
        KeyChainDocument document,
        CancellationToken cancellationToken)
    {
        await JsonSerializer.SerializeAsync(
            stream,
            document,
            KeyChainStorageJsonContext.Default.KeyChainDocument,
            cancellationToken);
    }

    public static byte[] WriteToUtf8Bytes(KeyChainDocument document)
        => JsonSerializer.SerializeToUtf8Bytes(
            document,
            KeyChainStorageJsonContext.Default.KeyChainDocument);

    public static string ComputePurposeHash(string purpose)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(purpose));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static KeyChainDocument Create(string purpose)
    {
        return new KeyChainDocument
        {
            FormatVersion = CurrentFormatVersion,
            Purpose = purpose,
            Keys = new List<KeyChainKeyRecord>()
        };
    }

    public static KeyChainKeyRecord MapToDocumentRecord(EncryptedKeyRecord record)
    {
        return new KeyChainKeyRecord
        {
            Id = record.Id,
            RsaKeyId = record.RsaKeyId,
            Algorithm = record.Algorithm,
            EncryptedKey = record.EncryptedKey,
            CreatedAt = record.CreatedAt,
            IsActive = record.IsActive
        };
    }

    public static EncryptedKeyRecord MapToRecord(string purpose, KeyChainKeyRecord record)
    {
        return new EncryptedKeyRecord
        {
            Id = record.Id,
            Purpose = purpose,
            RsaKeyId = record.RsaKeyId,
            Algorithm = record.Algorithm,
            EncryptedKey = record.EncryptedKey,
            CreatedAt = record.CreatedAt,
            IsActive = record.IsActive
        };
    }

    public static bool IsActiveKeyValid(EncryptedKeyRecord record, DateTimeOffset? rotateBefore)
        => rotateBefore is null || record.CreatedAt >= rotateBefore.Value;

    public static void ValidateCandidate(string purpose, EncryptedKeyRecord candidate)
    {
        if (!string.Equals(candidate.Purpose, purpose, StringComparison.Ordinal))
            throw new ArgumentException("Candidate purpose must match the requested purpose.", nameof(candidate));

        if (!candidate.IsActive)
            throw new ArgumentException("Candidate key must be active.", nameof(candidate));
    }

    public static void ValidateReplacement(EncryptedKeyRecord original, EncryptedKeyRecord replacement)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(replacement);

        if (replacement.Id != original.Id)
            throw new ArgumentException("Replacement key ID must match the original key ID.", nameof(replacement));

        if (!string.Equals(replacement.Purpose, original.Purpose, StringComparison.Ordinal))
            throw new ArgumentException("Replacement purpose must match the original purpose.", nameof(replacement));

        if (!string.Equals(replacement.Algorithm, original.Algorithm, StringComparison.Ordinal))
            throw new ArgumentException("Replacement algorithm must match the original algorithm.", nameof(replacement));

        if (replacement.CreatedAt != original.CreatedAt)
            throw new ArgumentException("Replacement creation time must match the original creation time.", nameof(replacement));

        if (replacement.IsActive != original.IsActive)
            throw new ArgumentException("Replacement active state must match the original active state.", nameof(replacement));

        if (string.IsNullOrWhiteSpace(replacement.RsaKeyId))
            throw new ArgumentException("Replacement RSA key ID cannot be null or whitespace.", nameof(replacement));

        if (string.IsNullOrWhiteSpace(replacement.EncryptedKey))
            throw new ArgumentException("Replacement encrypted key cannot be null or whitespace.", nameof(replacement));
    }

    public static bool WrapMatches(EncryptedKeyRecord current, EncryptedKeyRecord expected)
    {
        return string.Equals(current.RsaKeyId, expected.RsaKeyId, StringComparison.Ordinal)
            && string.Equals(current.EncryptedKey, expected.EncryptedKey, StringComparison.Ordinal);
    }

    public static void Validate(string source, KeyChainDocument document)
    {
        if (document.FormatVersion != CurrentFormatVersion)
            throw new FormatException($"Key chain document '{source}' has unsupported format version {document.FormatVersion}.");

        if (string.IsNullOrWhiteSpace(document.Purpose))
            throw new FormatException($"Key chain document '{source}' has a missing purpose.");

        if (document.Keys is null)
            throw new FormatException($"Key chain document '{source}' has a missing keys collection.");

        foreach (var key in document.Keys)
        {
            if (key.Id == Guid.Empty)
                throw new FormatException($"Key chain document '{source}' contains a key with an empty ID.");

            if (string.IsNullOrWhiteSpace(key.RsaKeyId))
                throw new FormatException($"Key chain document '{source}' contains a key with a missing RSA key ID.");

            if (string.IsNullOrWhiteSpace(key.Algorithm))
                throw new FormatException($"Key chain document '{source}' contains a key with a missing algorithm.");

            if (string.IsNullOrWhiteSpace(key.EncryptedKey))
                throw new FormatException($"Key chain document '{source}' contains a key with a missing encrypted key.");
        }
    }
}

internal sealed class KeyChainDocument
{
    [JsonPropertyName("formatVersion")]
    public int FormatVersion { get; set; }

    [JsonPropertyName("purpose")]
    public string Purpose { get; set; } = string.Empty;

    [JsonPropertyName("keys")]
    public List<KeyChainKeyRecord>? Keys { get; set; } = new();
}

internal sealed class KeyChainKeyRecord
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("rsaKeyId")]
    public string RsaKeyId { get; set; } = string.Empty;

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = string.Empty;

    [JsonPropertyName("encryptedKey")]
    public string EncryptedKey { get; set; } = string.Empty;

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; }

    [JsonPropertyName("isActive")]
    public bool IsActive { get; set; }
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(KeyChainDocument))]
internal partial class KeyChainStorageJsonContext : JsonSerializerContext;
