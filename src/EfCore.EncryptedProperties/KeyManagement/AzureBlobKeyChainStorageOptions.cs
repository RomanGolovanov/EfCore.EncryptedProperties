namespace EfCore.EncryptedProperties.KeyManagement;

public sealed class AzureBlobKeyChainStorageOptions
{
    public string? BlobPrefix { get; set; }
    public bool CreateContainerIfNotExists { get; set; }
    public int MaxWriteAttempts { get; set; } = 8;
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromMilliseconds(25);
}
