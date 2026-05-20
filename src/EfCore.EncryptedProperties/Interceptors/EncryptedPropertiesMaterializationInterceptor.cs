using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Infrastructure;
using EfCore.EncryptedProperties.Metadata;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Interceptors;

internal sealed class EncryptedPropertiesMaterializationInterceptor : IMaterializationInterceptor
{
    internal static readonly EncryptedPropertiesMaterializationInterceptor Instance = new();

    private EncryptedPropertiesMaterializationInterceptor()
    {
    }

    public object InitializedInstance(MaterializationInterceptionData materializationData, object entity)
    {
        var context = materializationData.Context;
        var services = GetServices(context);
        var model = GetModel(context, services.ModelCache);

        var entityTypeName = materializationData.EntityType.ClrType.FullName!;
        var descriptors = model.GetForEntityType(entityTypeName);

        if (descriptors.Count == 0)
            return entity;

        foreach (var descriptor in descriptors)
        {
            var payload = GetCiphertextPayload(materializationData, descriptor);

            if (descriptor.Mode == MaterializationMode.Lazy)
            {
                WireLazyProperty(entity, descriptor, payload, services);
            }
            else
            {
                DecryptProperty(entity, descriptor, payload, services);
            }
        }

        return entity;
    }

    private static void DecryptProperty(
        object entity,
        EncryptedPropertyDescriptor descriptor,
        string? payload,
        EncryptedPropertyServices services)
    {
        var plaintext = services.Cryptor
            .DecryptAsync(payload, descriptor.ClrType, descriptor.Context)
            .GetAwaiter()
            .GetResult();

        var assignedValue = plaintext ?? descriptor.DefaultValue;
        SetClrPropertyValue(entity, descriptor, assignedValue);
        services.StateTracker.Track(entity, descriptor, assignedValue, payload);
    }

    private static void WireLazyProperty(
        object entity,
        EncryptedPropertyDescriptor descriptor,
        string? payload,
        EncryptedPropertyServices services)
    {
        var accessor = new EncryptedValueAccessor(services.Cryptor, descriptor.Context);
        var encryptedValue = GetLazyAccessors(descriptor).CreateValue(payload, accessor);

        SetClrPropertyValue(entity, descriptor, encryptedValue);
        services.StateTracker.Track(entity, descriptor, plaintext: null, payload);
    }

    private static string? GetCiphertextPayload(
        MaterializationInterceptionData materializationData,
        EncryptedPropertyDescriptor descriptor)
    {
        var property = materializationData.EntityType.FindProperty(descriptor.CiphertextPropertyName);
        if (property is null)
            return null;

        return materializationData.GetPropertyValue<string?>(property);
    }

    private static void SetClrPropertyValue(object entity, EncryptedPropertyDescriptor descriptor, object? value)
    {
        descriptor.Accessors.SetValue(entity, value);
    }

    private static EncryptedValueAccessors GetLazyAccessors(EncryptedPropertyDescriptor descriptor)
    {
        return descriptor.Accessors.EncryptedValue
            ?? throw new InvalidOperationException(
                $"Encrypted property '{descriptor.EntityTypeName}.{descriptor.PropertyName}' is not configured for lazy encrypted values.");
    }

    private static EncryptedPropertyServices GetServices(DbContext context)
    {
        var efServices = ((IInfrastructure<IServiceProvider>)context).Instance;
        var applicationServices = GetApplicationServiceProvider(context);

        return new EncryptedPropertyServices(
            applicationServices.GetRequiredService<IEncryptedPropertyCryptor>(),
            applicationServices.GetRequiredService<EncryptedPropertyModelCache>(),
            efServices.GetRequiredService<EncryptedPropertyStateTracker>());
    }

    private static IServiceProvider GetApplicationServiceProvider(DbContext context)
    {
        var extension = context.GetService<IDbContextOptions>()
            .FindExtension<EncryptedPropertiesDbContextOptionsExtension>();

        return extension?.ApplicationServiceProvider
            ?? throw new InvalidOperationException(
                "Encrypted properties are not configured for this DbContext. Call UseEncryptedProperties when configuring the DbContext options.");
    }

    private static EncryptedPropertyModel GetModel(
        DbContext context,
        EncryptedPropertyModelCache modelCache)
    {
        return modelCache.GetOrAdd(context.Model);
    }

    private readonly record struct EncryptedPropertyServices(
        IEncryptedPropertyCryptor Cryptor,
        EncryptedPropertyModelCache ModelCache,
        EncryptedPropertyStateTracker StateTracker);
}
