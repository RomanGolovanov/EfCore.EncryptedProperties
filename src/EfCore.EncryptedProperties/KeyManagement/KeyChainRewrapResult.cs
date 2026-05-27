namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class KeyChainRewrapResult
{
    public required int ScannedCount { get; init; }
    public required int EligibleCount { get; init; }
    public required int RewrappedCount { get; init; }
    public required int AlreadyCurrentCount { get; init; }
    public required int WouldRewrapCount { get; init; }
    public required IReadOnlyList<KeyChainRewrapRecord> Records { get; init; }
}

public sealed class KeyChainRewrapRecord
{
    public required Guid KeyId { get; init; }
    public required string Purpose { get; init; }
    public required string OldRsaKeyId { get; init; }
    public required string NewRsaKeyId { get; init; }
    public required bool IsActive { get; init; }
    public required KeyChainRewrapStatus Status { get; init; }
}

public enum KeyChainRewrapStatus
{
    AlreadyCurrent,
    WouldRewrap,
    Rewrapped
}
