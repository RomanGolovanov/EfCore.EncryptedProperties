namespace EfCore.EncryptedProperties.Abstractions;

internal interface IEncryptedValueAccessor
{
    ValueTask<T?> DecryptAsync<T>(string? payload, CancellationToken cancellationToken = default);
}
