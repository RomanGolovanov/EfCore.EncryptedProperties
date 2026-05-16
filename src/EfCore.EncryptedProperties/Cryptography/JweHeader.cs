using System.Text.Json;
using System.Text.Json.Serialization;

namespace EfCore.EncryptedProperties.Cryptography;

internal sealed class JweHeader
{
    [JsonPropertyName("alg")]
    public required string Alg { get; init; }

    [JsonPropertyName("enc")]
    public required string Enc { get; init; }

    [JsonPropertyName("kid")]
    public required string Kid { get; init; }

    [JsonPropertyName("iv")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Iv { get; init; }

    [JsonPropertyName("tag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tag { get; init; }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, JsonContext.Default.JweHeader);
    }

    public static JweHeader FromJson(string json)
    {
        return JsonSerializer.Deserialize(json, JsonContext.Default.JweHeader)
            ?? throw new FormatException("Invalid JWE header JSON.");
    }
}

[JsonSerializable(typeof(JweHeader))]
internal partial class JsonContext : JsonSerializerContext;
