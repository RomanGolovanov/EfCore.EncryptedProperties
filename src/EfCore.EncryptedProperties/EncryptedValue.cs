using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties;

public sealed class EncryptedValue<T>
{
    private readonly IEncryptedValueAccessor? _accessor;
    private readonly string? _payload;
    private T? _plaintext;
    private bool _hasPlaintext;
    private bool _isModified;

    internal EncryptedValue(string? payload, IEncryptedValueAccessor accessor)
    {
        _payload = payload;
        _accessor = accessor;
    }

    private EncryptedValue(T? value)
    {
        _plaintext = value;
        _hasPlaintext = true;
        _isModified = true;
    }

    public static implicit operator EncryptedValue<T>(T value)
    {
        return new EncryptedValue<T>(value);
    }

    public async ValueTask<T?> GetDecryptedValueAsync(CancellationToken cancellationToken = default)
    {
        if (_hasPlaintext)
            return _plaintext;

        if (_accessor is null)
            return default;

        _plaintext = await _accessor.DecryptAsync<T>(_payload, cancellationToken);
        _hasPlaintext = true;
        return _plaintext;
    }

    internal bool IsModified => _isModified;
    internal T? PlaintextOrDefault => _plaintext;
    internal string? Payload => _payload;
}
