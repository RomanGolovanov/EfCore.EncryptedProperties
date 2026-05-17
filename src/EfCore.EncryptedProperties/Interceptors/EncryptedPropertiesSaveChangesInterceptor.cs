using System.Collections.Concurrent;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Infrastructure;
using EfCore.EncryptedProperties.Metadata;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Interceptors;

internal sealed class EncryptedPropertiesSaveChangesInterceptor : SaveChangesInterceptor
{
    private readonly IEncryptedPropertyCryptor _cryptor;
    private readonly ConcurrentDictionary<IModel, EncryptedPropertyModel> _models = new();

    public EncryptedPropertiesSaveChangesInterceptor(IEncryptedPropertyCryptor cryptor)
    {
        _cryptor = cryptor;
    }

    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        var context = eventData.Context;
        if (context is null)
            return result;

        ProcessSavingChanges(context, cancellationToken: default);
        return result;
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        var context = eventData.Context;
        if (context is null)
            return result;

        await ProcessSavingChangesAsync(context, cancellationToken);
        return result;
    }

    private void ProcessSavingChanges(DbContext context, CancellationToken cancellationToken)
    {
        var model = GetModel(context);
        if (model.Properties.Count == 0)
            return;

        var services = GetServices(context);

        foreach (var entry in GetProcessableEntries(context))
        {
            foreach (var descriptor in model.GetForEntityType(entry.Metadata.ClrType.FullName!))
            {
                if (descriptor.Mode == MaterializationMode.Lazy)
                {
                    var encrypt = (object? plaintext, EncryptedPropertyContext propertyContext) =>
                        services.Cryptor.EncryptAsync(plaintext, propertyContext, cancellationToken).GetAwaiter().GetResult();

                    ProcessLazyPropertySave(entry, descriptor, services, encrypt);
                }
                else
                {
                    var encrypt = (object? plaintext, EncryptedPropertyContext propertyContext) =>
                        services.Cryptor.EncryptAsync(plaintext, propertyContext, cancellationToken).GetAwaiter().GetResult();

                    ProcessDecryptOnReadPropertySave(entry, descriptor, services, encrypt);
                }
            }
        }
    }

    private async Task ProcessSavingChangesAsync(DbContext context, CancellationToken cancellationToken)
    {
        var model = GetModel(context);
        if (model.Properties.Count == 0)
            return;

        var services = GetServices(context);

        foreach (var entry in GetProcessableEntries(context))
        {
            foreach (var descriptor in model.GetForEntityType(entry.Metadata.ClrType.FullName!))
            {
                if (descriptor.Mode == MaterializationMode.Lazy)
                {
                    await ProcessLazyPropertySaveAsync(entry, descriptor, services, cancellationToken);
                }
                else
                {
                    await ProcessDecryptOnReadPropertySaveAsync(entry, descriptor, services, cancellationToken);
                }
            }
        }
    }

    private static async Task ProcessDecryptOnReadPropertySaveAsync(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        CancellationToken cancellationToken)
    {
        await ProcessDecryptOnReadPropertySaveAsync(
            entry,
            descriptor,
            services,
            async (plaintext, propertyContext) =>
                await services.Cryptor.EncryptAsync(plaintext, propertyContext, cancellationToken));
    }

    private static Task ProcessDecryptOnReadPropertySaveAsync(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        Func<object?, EncryptedPropertyContext, ValueTask<string?>> encrypt)
    {
        var currentValue = GetClrPropertyValue(entry.Entity, descriptor);

        if (!ShouldWriteDecryptOnReadValue(entry, descriptor, services.StateTracker, currentValue))
            return Task.CompletedTask;

        return WriteDecryptOnReadValueAsync(entry, descriptor, services, currentValue, encrypt);
    }

    private static void ProcessDecryptOnReadPropertySave(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        Func<object?, EncryptedPropertyContext, string?> encrypt)
    {
        var currentValue = GetClrPropertyValue(entry.Entity, descriptor);

        if (!ShouldWriteDecryptOnReadValue(entry, descriptor, services.StateTracker, currentValue))
            return;

        var payload = encrypt(currentValue, descriptor.Context);
        WriteCiphertext(entry, descriptor, payload);
        services.StateTracker.Track(entry.Entity, descriptor, currentValue, payload);
    }

    private static async Task WriteDecryptOnReadValueAsync(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        object? currentValue,
        Func<object?, EncryptedPropertyContext, ValueTask<string?>> encrypt)
    {
        var payload = await encrypt(currentValue, descriptor.Context);
        WriteCiphertext(entry, descriptor, payload);
        services.StateTracker.Track(entry.Entity, descriptor, currentValue, payload);
    }

    private static async Task ProcessLazyPropertySaveAsync(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        CancellationToken cancellationToken)
    {
        await ProcessLazyPropertySaveAsync(
            entry,
            descriptor,
            services,
            async (plaintext, propertyContext) =>
                await services.Cryptor.EncryptAsync(plaintext, propertyContext, cancellationToken));
    }

    private static Task ProcessLazyPropertySaveAsync(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        Func<object?, EncryptedPropertyContext, ValueTask<string?>> encrypt)
    {
        var currentValue = GetClrPropertyValue(entry.Entity, descriptor);
        return ProcessLazyPropertySaveCoreAsync(entry, descriptor, services, currentValue, encrypt);
    }

    private static void ProcessLazyPropertySave(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        Func<object?, EncryptedPropertyContext, string?> encrypt)
    {
        var currentValue = GetClrPropertyValue(entry.Entity, descriptor);
        ProcessLazyPropertySaveCore(entry, descriptor, services, currentValue, encrypt);
    }

    private static async Task ProcessLazyPropertySaveCoreAsync(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        object? currentValue,
        Func<object?, EncryptedPropertyContext, ValueTask<string?>> encrypt)
    {
        if (currentValue is null)
        {
            WriteNullLazyValueIfChanged(entry, descriptor, services);
            return;
        }

        var lazyAccessors = GetLazyAccessors(descriptor);
        if (!lazyAccessors.ValueType.IsInstanceOfType(currentValue))
            return;

        var isModified = lazyAccessors.GetIsModified(currentValue);
        var payload = lazyAccessors.GetPayload(currentValue);

        if (!isModified)
        {
            if (entry.State == EntityState.Added || ShouldWriteExistingLazyPayload(entry, descriptor, services, payload))
            {
                WriteCiphertext(entry, descriptor, payload);
                services.StateTracker.Track(entry.Entity, descriptor, plaintext: null, payload);
            }

            return;
        }

        var plaintext = lazyAccessors.GetPlaintext(currentValue);
        var encryptedPayload = await encrypt(plaintext, descriptor.Context);
        WriteLazyEncryptedValue(entry, descriptor, services, plaintext, encryptedPayload);
    }

    private static void ProcessLazyPropertySaveCore(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        object? currentValue,
        Func<object?, EncryptedPropertyContext, string?> encrypt)
    {
        if (currentValue is null)
        {
            WriteNullLazyValueIfChanged(entry, descriptor, services);
            return;
        }

        var lazyAccessors = GetLazyAccessors(descriptor);
        if (!lazyAccessors.ValueType.IsInstanceOfType(currentValue))
            return;

        var isModified = lazyAccessors.GetIsModified(currentValue);
        var payload = lazyAccessors.GetPayload(currentValue);

        if (!isModified)
        {
            if (entry.State == EntityState.Added || ShouldWriteExistingLazyPayload(entry, descriptor, services, payload))
            {
                WriteCiphertext(entry, descriptor, payload);
                services.StateTracker.Track(entry.Entity, descriptor, plaintext: null, payload);
            }

            return;
        }

        var plaintext = lazyAccessors.GetPlaintext(currentValue);
        var encryptedPayload = encrypt(plaintext, descriptor.Context);
        WriteLazyEncryptedValue(entry, descriptor, services, plaintext, encryptedPayload);
    }

    private static void WriteNullLazyValueIfChanged(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services)
    {
        var shouldWrite = entry.State == EntityState.Added;

        if (!shouldWrite
            && services.StateTracker.TryGet(entry.Entity, descriptor, out var snapshot)
            && snapshot.Payload is not null)
        {
            shouldWrite = true;
        }

        if (!shouldWrite)
            return;

        WriteCiphertext(entry, descriptor, payload: null);
        services.StateTracker.Track(entry.Entity, descriptor, plaintext: null, payload: null);
    }

    private static bool ShouldWriteExistingLazyPayload(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        string? payload)
    {
        if (!services.StateTracker.TryGet(entry.Entity, descriptor, out var snapshot))
            return entry.State == EntityState.Modified && payload is not null;

        return !string.Equals(snapshot.Payload, payload, StringComparison.Ordinal);
    }

    private static void WriteLazyEncryptedValue(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyServices services,
        object? plaintext,
        string? payload)
    {
        WriteCiphertext(entry, descriptor, payload);

        var accessor = new EncryptedValueAccessor(services.Cryptor, descriptor.Context);
        var newValue = GetLazyAccessors(descriptor).CreateValue(payload, accessor);
        SetClrPropertyValue(entry.Entity, descriptor, newValue);
        services.StateTracker.Track(entry.Entity, descriptor, plaintext, payload);
    }

    private static bool ShouldWriteDecryptOnReadValue(
        EntityEntry entry,
        EncryptedPropertyDescriptor descriptor,
        EncryptedPropertyStateTracker stateTracker,
        object? currentValue)
    {
        if (entry.State == EntityState.Added)
            return true;

        if (!stateTracker.TryGet(entry.Entity, descriptor, out var snapshot))
            return entry.State == EntityState.Modified;

        return !EncryptedPropertyStateTracker.ValueEquals(snapshot.Plaintext, currentValue);
    }

    private static IReadOnlyList<EntityEntry> GetProcessableEntries(DbContext context)
    {
        return context.ChangeTracker.Entries()
            .Where(e => e.State is EntityState.Added or EntityState.Modified or EntityState.Unchanged)
            .ToList();
    }

    private static void WriteCiphertext(EntityEntry entry, EncryptedPropertyDescriptor descriptor, string? payload)
    {
        var propertyEntry = entry.Property(descriptor.CiphertextPropertyName);
        propertyEntry.CurrentValue = payload;

        if (entry.State != EntityState.Added)
            propertyEntry.IsModified = true;
    }

    private static object? GetClrPropertyValue(object entity, EncryptedPropertyDescriptor descriptor)
    {
        return descriptor.Accessors.GetValue(entity);
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
        return _models.GetOrAdd(context.Model, EncryptedPropertyModelBuilder.Build);
    }

    private readonly record struct EncryptedPropertyServices(
        IEncryptedPropertyCryptor Cryptor,
        EncryptedPropertyStateTracker StateTracker);
}
