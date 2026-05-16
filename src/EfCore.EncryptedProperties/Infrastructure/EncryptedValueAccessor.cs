using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;

namespace EfCore.EncryptedProperties.Infrastructure;

internal sealed class EncryptedValueAccessor : IEncryptedValueAccessor
{
    private readonly IEncryptedPropertyCryptor _cryptor;
    private readonly EncryptedPropertyContext _context;

    public EncryptedValueAccessor(IEncryptedPropertyCryptor cryptor, EncryptedPropertyContext context)
    {
        _cryptor = cryptor;
        _context = context;
    }

    public async ValueTask<T?> DecryptAsync<T>(string? payload, CancellationToken cancellationToken = default)
    {
        var result = await _cryptor.DecryptAsync(payload, typeof(T), _context, cancellationToken);
        return result is null ? default : (T)result;
    }
}

internal sealed class NullEncryptedValueAccessor : IEncryptedValueAccessor
{
    public static readonly NullEncryptedValueAccessor Instance = new();

    public ValueTask<T?> DecryptAsync<T>(string? payload, CancellationToken cancellationToken = default)
    {
        return new ValueTask<T?>(default(T));
    }
}
