using System.Linq.Expressions;
using System.Reflection;
using EfCore.EncryptedProperties.Abstractions;

namespace EfCore.EncryptedProperties.Metadata;

internal sealed class EncryptedValueAccessors
{
    private EncryptedValueAccessors(
        Type valueType,
        Func<string?, IEncryptedValueAccessor, object> create,
        Func<object, bool> getIsModified,
        Func<object, string?> getPayload,
        Func<object, object?> getPlaintext)
    {
        ValueType = valueType;
        CreateValue = create;
        GetIsModified = getIsModified;
        GetPayload = getPayload;
        GetPlaintext = getPlaintext;
    }

    public Type ValueType { get; }
    public Func<string?, IEncryptedValueAccessor, object> CreateValue { get; }
    public Func<object, bool> GetIsModified { get; }
    public Func<object, string?> GetPayload { get; }
    public Func<object, object?> GetPlaintext { get; }

    public static EncryptedValueAccessors Create(Type encryptedValueType)
    {
        if (!encryptedValueType.IsGenericType
            || encryptedValueType.GetGenericTypeDefinition() != typeof(EncryptedValue<>))
        {
            throw new InvalidOperationException(
                $"Lazy encrypted property type '{encryptedValueType.FullName}' must be EncryptedValue<T>.");
        }

        return new EncryptedValueAccessors(
            encryptedValueType,
            CompileFactory(encryptedValueType),
            CompilePropertyGetter<bool>(encryptedValueType, "IsModified"),
            CompilePropertyGetter<string?>(encryptedValueType, "Payload"),
            CompileBoxedPropertyGetter(encryptedValueType, "PlaintextOrDefault"));
    }

    private static Func<string?, IEncryptedValueAccessor, object> CompileFactory(Type encryptedValueType)
    {
        var constructor = encryptedValueType.GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                types: [typeof(string), typeof(IEncryptedValueAccessor)],
                modifiers: null)
            ?? throw new InvalidOperationException(
                $"Encrypted value type '{encryptedValueType.FullName}' is missing the expected internal constructor.");

        var payload = Expression.Parameter(typeof(string), "payload");
        var accessor = Expression.Parameter(typeof(IEncryptedValueAccessor), "accessor");
        var instance = Expression.New(constructor, payload, accessor);
        var boxedInstance = Expression.Convert(instance, typeof(object));

        return Expression
            .Lambda<Func<string?, IEncryptedValueAccessor, object>>(boxedInstance, payload, accessor)
            .Compile();
    }

    private static Func<object, TValue> CompilePropertyGetter<TValue>(Type type, string propertyName)
    {
        var instance = Expression.Parameter(typeof(object), "instance");
        var typedInstance = Expression.Convert(instance, type);
        var property = Expression.Property(typedInstance, GetInternalProperty(type, propertyName));

        return Expression.Lambda<Func<object, TValue>>(property, instance).Compile();
    }

    private static Func<object, object?> CompileBoxedPropertyGetter(Type type, string propertyName)
    {
        var instance = Expression.Parameter(typeof(object), "instance");
        var typedInstance = Expression.Convert(instance, type);
        var property = Expression.Property(typedInstance, GetInternalProperty(type, propertyName));
        var boxedProperty = Expression.Convert(property, typeof(object));

        return Expression.Lambda<Func<object, object?>>(boxedProperty, instance).Compile();
    }

    private static PropertyInfo GetInternalProperty(Type type, string propertyName)
    {
        return type.GetProperty(propertyName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                $"Encrypted value type '{type.FullName}' is missing the expected '{propertyName}' property.");
    }
}
