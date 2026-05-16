using EfCore.EncryptedProperties.Configuration;

namespace EfCore.EncryptedProperties.Abstractions;

public interface IEncryptedPropertyCryptor
{
    ValueTask<string?> EncryptAsync(
        object? value,
        EncryptedPropertyContext context,
        CancellationToken cancellationToken = default);

    ValueTask<object?> DecryptAsync(
        string? payload,
        Type targetType,
        EncryptedPropertyContext context,
        CancellationToken cancellationToken = default);
}
