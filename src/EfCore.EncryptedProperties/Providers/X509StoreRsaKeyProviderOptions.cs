using System.Security.Cryptography.X509Certificates;

namespace EfCore.EncryptedProperties.Providers;

public sealed class X509StoreRsaKeyProviderOptions
{
    public StoreLocation StoreLocation { get; set; } = StoreLocation.CurrentUser;
    public string StoreName { get; set; } = "My";
    public string? CurrentCertificateThumbprint { get; set; }
    public bool ValidateCurrentCertificateTime { get; set; } = true;
    public bool ValidateKeyUsage { get; set; } = true;
}
