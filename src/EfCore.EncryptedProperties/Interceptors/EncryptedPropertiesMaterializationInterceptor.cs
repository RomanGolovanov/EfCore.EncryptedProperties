using System.Collections.Concurrent;
using System.Reflection;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
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
    private readonly ConcurrentDictionary<IModel, EncryptedPropertyModel> _models = new();

    public EncryptedPropertiesMaterializationInterceptor(IEncryptedPropertyCryptor cryptor)
    {
        _cryptor = cryptor;
    }

    public object InitializedInstance(MaterializationInterceptionData materializationData, object entity)
    {
        var context = materializationData.Context;
        var model = GetModel(context);

        var entityTypeName = materializationData.EntityType.ClrType.FullName!;
        var descriptors = model.GetForEntityType(entityTypeName).ToList();

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
        var propertyContext = CreatePropertyContext(descriptor);
        var plaintext = services.Cryptor
            .DecryptAsync(payload, descriptor.ClrType, propertyContext)
            .GetAwaiter()
            .GetResult();

        var assignedValue = GetAssignableValue(plaintext, descriptor.ClrType);
        SetClrPropertyValue(entity, descriptor, assignedValue);
        services.StateTracker.Track(entity, descriptor, assignedValue, payload);
    }

    private static void WireLazyProperty(
        object entity,
        EncryptedPropertyDescriptor descriptor,
        string? payload,
        EncryptedPropertyServices services)
    {
        var propertyContext = CreatePropertyContext(descriptor);
        var accessor = new EncryptedValueAccessor(services.Cryptor, propertyContext);
        var encryptedValue = CreateEncryptedValue(descriptor.ClrType, payload, accessor);

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

    private static object? GetAssignableValue(object? value, Type targetType)
    {
        if (value is not null)
            return value;

        return targetType.IsValueType && Nullable.GetUnderlyingType(targetType) is null
            ? Activator.CreateInstance(targetType)
            : null;
    }

    private static void SetClrPropertyValue(object entity, EncryptedPropertyDescriptor descriptor, object? value)
    {
        var property = entity.GetType().GetProperty(
                descriptor.PropertyName,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                $"Encrypted property '{entity.GetType().FullName}.{descriptor.PropertyName}' was not found.");

        property.SetValue(entity, value);
    }

    private static object CreateEncryptedValue(Type innerType, string? payload, IEncryptedValueAccessor accessor)
    {
        var encryptedValueType = typeof(EncryptedValue<>).MakeGenericType(innerType);
        return Activator.CreateInstance(
            encryptedValueType,
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: [payload, accessor],
            culture: null)!;
    }

    private static EncryptedPropertyContext CreatePropertyContext(EncryptedPropertyDescriptor descriptor)
    {
        return new EncryptedPropertyContext
        {
            Purpose = descriptor.Purpose,
            EntityTypeName = descriptor.EntityTypeName,
            PropertyName = descriptor.PropertyName
        };
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
        return _models.GetOrAdd(context.Model, EncryptedPropertyModelBuilder.Build);
    }

    private readonly record struct EncryptedPropertyServices(
        IEncryptedPropertyCryptor Cryptor,
        EncryptedPropertyStateTracker StateTracker);
}
