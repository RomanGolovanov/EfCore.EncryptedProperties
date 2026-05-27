using Microsoft.Extensions.Logging;

namespace EfCore.EncryptedProperties;

public static class EncryptedPropertiesEventIds
{
    public static readonly EventId KeyCreated = new(1000, nameof(KeyCreated));
    public static readonly EventId KeyRotated = new(1001, nameof(KeyRotated));
    public static readonly EventId KeyPreloadFailed = new(1002, nameof(KeyPreloadFailed));
    public static readonly EventId DecryptionFailed = new(1003, nameof(DecryptionFailed));
    public static readonly EventId EncryptedPropertyModelDiscovered = new(1004, nameof(EncryptedPropertyModelDiscovered));
    public static readonly EventId EncryptedPropertyDiscovered = new(1005, nameof(EncryptedPropertyDiscovered));
    public static readonly EventId KeyRewrapped = new(1006, nameof(KeyRewrapped));
    public static readonly EventId KeyRewrapFailed = new(1007, nameof(KeyRewrapFailed));
}
