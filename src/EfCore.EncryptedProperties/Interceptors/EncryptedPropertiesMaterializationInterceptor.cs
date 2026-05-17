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
    private readonly IEncryptedPropertyCryptor _cryptor;
    private readonly EncryptedPropertyModelCache _modelCache;

    public EncryptedPropertiesMaterializationInterceptor(
        IEncryptedPropertyCryptor cryptor,
        EncryptedPropertyModelCache? modelCache = null)
    {
        _cryptor = cryptor;
        _modelCache = modelCache ?? new EncryptedPropertyModelCache();
    }

    public object InitializedInstance(MaterializationInterceptionData materializationData, object entity)
    {
        var context = materializationData.Context;
        var model = GetModel(context);

        var entityTypeName = materializationData.EntityType.ClrType.FullName!;
        var descriptors = model.GetForEntityType(entityTypeName);

        if (descriptors.Count == 0)
            return entity;

        var services = GetServices(context);

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

    private EncryptedPropertyServices GetServices(DbContext context)
    {
        var sp = ((IInfrastructure<IServiceProvider>)context).Instance;
        return new EncryptedPropertyServices(
            _cryptor,
            sp.GetRequiredService<EncryptedPropertyStateTracker>());
    }

    private EncryptedPropertyModel GetModel(DbContext context)
    {
        return _modelCache.GetOrAdd(context.Model);
    }

    private readonly record struct EncryptedPropertyServices(
        IEncryptedPropertyCryptor Cryptor,
        EncryptedPropertyStateTracker StateTracker);
}
