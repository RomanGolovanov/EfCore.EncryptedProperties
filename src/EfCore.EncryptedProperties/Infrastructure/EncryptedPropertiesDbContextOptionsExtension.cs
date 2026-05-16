using System.Runtime.CompilerServices;
using EfCore.EncryptedProperties.Abstractions;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata.Conventions.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Infrastructure;

internal sealed class EncryptedPropertiesDbContextOptionsExtension : IDbContextOptionsExtension
{
    private readonly IEncryptedPropertyCryptor _cryptor;
    private DbContextOptionsExtensionInfo? _info;

    public EncryptedPropertiesDbContextOptionsExtension(IEncryptedPropertyCryptor cryptor)
    {
        _cryptor = cryptor;
    }

    public DbContextOptionsExtensionInfo Info => _info ??= new ExtensionInfo(this);

    public void ApplyServices(IServiceCollection services)
    {
        services.AddSingleton<IConventionSetPlugin, EncryptedPropertiesConventionSetPlugin>();
        services.AddSingleton(_cryptor);
        services.AddScoped<EncryptedPropertyStateTracker>();
    }

    public void Validate(IDbContextOptions options)
    {
    }

    private sealed class ExtensionInfo : DbContextOptionsExtensionInfo
    {
        private readonly EncryptedPropertiesDbContextOptionsExtension _extension;

        public ExtensionInfo(IDbContextOptionsExtension extension) : base(extension)
        {
            _extension = (EncryptedPropertiesDbContextOptionsExtension)extension;
        }

        public override bool IsDatabaseProvider => false;
        public override string LogFragment => "using EncryptedProperties ";

        public override int GetServiceProviderHashCode()
            => RuntimeHelpers.GetHashCode(_extension._cryptor);

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other)
            => other is ExtensionInfo otherInfo
                && ReferenceEquals(_extension._cryptor, otherInfo._extension._cryptor);

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo)
        {
            debugInfo["EncryptedProperties:Enabled"] = "true";
        }
    }
}
