using EfCore.EncryptedProperties.Configuration;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata.Conventions.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Infrastructure;

internal sealed class EncryptedPropertiesDbContextOptionsExtension : IDbContextOptionsExtension
{
    private DbContextOptionsExtensionInfo? _info;

    public EncryptedPropertiesDbContextOptionsExtension(IServiceProvider applicationServiceProvider)
    {
        ApplicationServiceProvider = applicationServiceProvider;
        CustomValueSerializerTypes = applicationServiceProvider
            .GetRequiredService<EncryptedPropertiesOptions>()
            .CustomValueSerializerTypes;
    }

    internal IServiceProvider ApplicationServiceProvider { get; }
    internal IReadOnlyList<Type> CustomValueSerializerTypes { get; }

    public DbContextOptionsExtensionInfo Info => _info ??= new ExtensionInfo(this);

    public void ApplyServices(IServiceCollection services)
    {
        services.AddSingleton<IConventionSetPlugin>(
            new EncryptedPropertiesConventionSetPlugin(CustomValueSerializerTypes));
        services.AddScoped<EncryptedPropertyStateTracker>();
    }

    public void Validate(IDbContextOptions options)
    {
    }

    private sealed class ExtensionInfo : DbContextOptionsExtensionInfo
    {
        private readonly EncryptedPropertiesDbContextOptionsExtension _extension;

        public ExtensionInfo(EncryptedPropertiesDbContextOptionsExtension extension) : base(extension)
        {
            _extension = extension;
        }

        public override bool IsDatabaseProvider => false;
        public override string LogFragment => "using EncryptedProperties ";

        public override int GetServiceProviderHashCode()
        {
            var hash = new HashCode();
            foreach (var type in _extension.CustomValueSerializerTypes)
                hash.Add(type.AssemblyQualifiedName, StringComparer.Ordinal);

            return hash.ToHashCode();
        }

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other)
            => other is ExtensionInfo otherInfo
                && _extension.CustomValueSerializerTypes.SequenceEqual(otherInfo._extension.CustomValueSerializerTypes);

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo)
        {
            debugInfo["EncryptedProperties:Enabled"] = "true";
            debugInfo["EncryptedProperties:CustomValueSerializers"] = string.Join(
                ",",
                _extension.CustomValueSerializerTypes.Select(type => type.AssemblyQualifiedName));
        }
    }
}
