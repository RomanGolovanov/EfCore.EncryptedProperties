using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Providers;

public sealed class X509StoreRsaKeyProvider : IRsaKeyProvider
{
    private const string KeyIdPrefix = "x509store";
    private const string AlgorithmName = "RSA-OAEP-256";
    private readonly X509StoreRsaKeyProviderOptions _options;
    private readonly string _currentCertificateThumbprint;

    public X509StoreRsaKeyProvider(X509StoreRsaKeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!Enum.IsDefined(options.StoreLocation))
            throw new ArgumentOutOfRangeException(nameof(options.StoreLocation), "Store location is not valid.");

        var storeName = NormalizeStoreName(options.StoreName);
        _currentCertificateThumbprint = NormalizeThumbprint(
            options.CurrentCertificateThumbprint,
            nameof(options.CurrentCertificateThumbprint));

        _options = new X509StoreRsaKeyProviderOptions
        {
            StoreLocation = options.StoreLocation,
            StoreName = storeName,
            CurrentCertificateThumbprint = _currentCertificateThumbprint,
            ValidateCurrentCertificateTime = options.ValidateCurrentCertificateTime,
            ValidateKeyUsage = options.ValidateKeyUsage
        };

        KeyId = CreateKeyId(_options.StoreLocation, _options.StoreName, _currentCertificateThumbprint);
    }

    public string KeyId { get; }
    public string Algorithm => AlgorithmName;

    public ValueTask<RsaKeyWrapResult> WrapKeyAsync(
        byte[] plaintext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();

        using var certificate = FindCertificate(
            _options.StoreLocation,
            _options.StoreName,
            _currentCertificateThumbprint);

        ValidateCurrentCertificate(certificate);

        using var publicKey = certificate.GetRSAPublicKey()
            ?? throw CreateCertificateException(
                _options.StoreLocation,
                _options.StoreName,
                _currentCertificateThumbprint,
                "does not have an RSA public key");

        var ciphertext = publicKey.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<RsaKeyWrapResult>(
            new RsaKeyWrapResult(ciphertext, KeyId, Algorithm));
    }

    public ValueTask<byte[]> UnwrapKeyAsync(
        byte[] ciphertext,
        string rsaKeyId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        cancellationToken.ThrowIfCancellationRequested();

        var keyId = ParseKeyId(rsaKeyId);
        using var certificate = FindCertificate(keyId.StoreLocation, keyId.StoreName, keyId.Thumbprint);
        using var privateKey = GetPrivateKey(certificate, keyId.StoreLocation, keyId.StoreName, keyId.Thumbprint);

        var plaintext = privateKey.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return new ValueTask<byte[]>(plaintext);
    }

    private void ValidateCurrentCertificate(X509Certificate2 certificate)
    {
        using var privateKey = GetPrivateKey(
            certificate,
            _options.StoreLocation,
            _options.StoreName,
            _currentCertificateThumbprint);

        if (_options.ValidateCurrentCertificateTime)
            ValidateCertificateTime(certificate);

        if (_options.ValidateKeyUsage)
            ValidateCertificateKeyUsage(certificate);
    }

    private static RSA GetPrivateKey(
        X509Certificate2 certificate,
        StoreLocation storeLocation,
        string storeName,
        string thumbprint)
    {
        if (!certificate.HasPrivateKey)
        {
            throw CreateCertificateException(
                storeLocation,
                storeName,
                thumbprint,
                "does not have an RSA private key");
        }

        try
        {
            return certificate.GetRSAPrivateKey()
                ?? throw CreateCertificateException(
                    storeLocation,
                    storeName,
                    thumbprint,
                    "does not have an RSA private key");
        }
        catch (CryptographicException ex)
        {
            throw CreateCertificateException(
                storeLocation,
                storeName,
                thumbprint,
                "has an RSA private key, but it could not be opened",
                ex);
        }
    }

    private void ValidateCertificateTime(X509Certificate2 certificate)
    {
        var now = DateTimeOffset.UtcNow;
        var notBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);

        if (now < notBefore || now > notAfter)
        {
            throw CreateCertificateException(
                _options.StoreLocation,
                _options.StoreName,
                _currentCertificateThumbprint,
                $"is not valid at the current time. Valid from {notBefore:O} to {notAfter:O}");
        }
    }

    private void ValidateCertificateKeyUsage(X509Certificate2 certificate)
    {
        var keyUsage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();

        if (keyUsage is null)
            return;

        const X509KeyUsageFlags allowed =
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment;

        if ((keyUsage.KeyUsages & allowed) == 0)
        {
            throw CreateCertificateException(
                _options.StoreLocation,
                _options.StoreName,
                _currentCertificateThumbprint,
                "does not allow key encipherment or data encipherment");
        }
    }

    private static X509Certificate2 FindCertificate(
        StoreLocation storeLocation,
        string storeName,
        string thumbprint)
    {
        using var store = new X509Store(storeName, storeLocation);
        try
        {
            store.Open(OpenFlags.ReadOnly);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException(
                $"Could not open X.509 certificate store '{FormatStoreName(storeLocation, storeName)}'.",
                ex);
        }

        var matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint,
            validOnly: false);

        if (matches.Count == 0)
        {
            throw new InvalidOperationException(
                $"Certificate '{thumbprint}' was not found in X.509 certificate store '{FormatStoreName(storeLocation, storeName)}'.");
        }

        return new X509Certificate2(matches[0]);
    }

    private static ParsedKeyId ParseKeyId(string rsaKeyId)
    {
        if (string.IsNullOrWhiteSpace(rsaKeyId))
            throw new ArgumentException("RSA key ID cannot be null or whitespace.", nameof(rsaKeyId));

        var parts = rsaKeyId.Split(':');
        if (parts.Length != 4 || !string.Equals(parts[0], KeyIdPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"RSA key ID '{rsaKeyId}' is not an X.509 store key ID. Expected '{KeyIdPrefix}:{{StoreLocation}}:{{StoreName}}:{{Thumbprint}}'.");
        }

        if (!Enum.TryParse<StoreLocation>(parts[1], ignoreCase: true, out var storeLocation)
            || !Enum.IsDefined(storeLocation))
        {
            throw new InvalidOperationException($"RSA key ID '{rsaKeyId}' contains an invalid X.509 store location.");
        }

        var storeName = NormalizeStoreName(parts[2]);
        var thumbprint = NormalizeThumbprint(parts[3], nameof(rsaKeyId));
        return new ParsedKeyId(storeLocation, storeName, thumbprint);
    }

    private static string CreateKeyId(
        StoreLocation storeLocation,
        string storeName,
        string thumbprint)
        => $"{KeyIdPrefix}:{storeLocation}:{storeName}:{thumbprint}";

    private static string NormalizeStoreName(string? storeName)
    {
        if (string.IsNullOrWhiteSpace(storeName))
            throw new ArgumentException("X.509 store name cannot be null or whitespace.", nameof(storeName));

        if (storeName.Contains(':', StringComparison.Ordinal))
            throw new ArgumentException("X.509 store name cannot contain ':'.", nameof(storeName));

        return storeName.Trim();
    }

    private static string NormalizeThumbprint(string? thumbprint, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
            throw new ArgumentException("Certificate thumbprint cannot be null or whitespace.", parameterName);

        var builder = new StringBuilder(40);
        foreach (var ch in thumbprint)
        {
            if (char.IsWhiteSpace(ch) || ch is ':' or '-')
                continue;

            if (!Uri.IsHexDigit(ch))
            {
                throw new ArgumentException(
                    "Certificate thumbprint must contain only hexadecimal characters, whitespace, ':' or '-'.",
                    parameterName);
            }

            builder.Append(char.ToUpperInvariant(ch));
        }

        if (builder.Length != 40)
        {
            throw new ArgumentException(
                "Certificate thumbprint must be a SHA-1 thumbprint containing 40 hexadecimal characters.",
                parameterName);
        }

        return builder.ToString();
    }

    private static InvalidOperationException CreateCertificateException(
        StoreLocation storeLocation,
        string storeName,
        string thumbprint,
        string message,
        Exception? innerException = null)
    {
        return new InvalidOperationException(
            $"Certificate '{thumbprint}' in X.509 certificate store '{FormatStoreName(storeLocation, storeName)}' {message}.",
            innerException);
    }

    private static string FormatStoreName(StoreLocation storeLocation, string storeName)
        => $"{storeLocation}\\{storeName}";

    private sealed record ParsedKeyId(
        StoreLocation StoreLocation,
        string StoreName,
        string Thumbprint);
}
