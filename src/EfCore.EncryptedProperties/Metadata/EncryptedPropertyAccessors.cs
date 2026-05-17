using System.Linq.Expressions;
using System.Reflection;

namespace EfCore.EncryptedProperties.Metadata;

internal sealed class EncryptedPropertyAccessors
{
    private EncryptedPropertyAccessors(
        Func<object, object?> getValue,
        Action<object, object?> setValue,
        EncryptedValueAccessors? encryptedValue)
    {
        GetValue = getValue;
        SetValue = setValue;
        EncryptedValue = encryptedValue;
    }

    public Func<object, object?> GetValue { get; }
    public Action<object, object?> SetValue { get; }
    public EncryptedValueAccessors? EncryptedValue { get; }

    public static EncryptedPropertyAccessors Create(
        Type entityType,
        string propertyName,
        MaterializationMode mode)
    {
        var property = entityType.GetProperty(
                propertyName,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                $"Encrypted property '{entityType.FullName}.{propertyName}' was not found.");

        var encryptedValue = mode == MaterializationMode.Lazy
            ? EncryptedValueAccessors.Create(property.PropertyType)
            : null;

        return new EncryptedPropertyAccessors(
            CompileGetter(property),
            CompileSetter(property),
            encryptedValue);
    }

    private static Func<object, object?> CompileGetter(PropertyInfo property)
    {
        var entity = Expression.Parameter(typeof(object), "entity");
        var typedEntity = Expression.Convert(entity, property.DeclaringType!);
        var propertyValue = Expression.Property(typedEntity, property);
        var boxedValue = Expression.Convert(propertyValue, typeof(object));

        return Expression.Lambda<Func<object, object?>>(boxedValue, entity).Compile();
    }

    private static Action<object, object?> CompileSetter(PropertyInfo property)
    {
        var entity = Expression.Parameter(typeof(object), "entity");
        var value = Expression.Parameter(typeof(object), "value");
        var typedEntity = Expression.Convert(entity, property.DeclaringType!);
        var typedValue = Expression.Convert(value, property.PropertyType);
        var assignment = Expression.Assign(Expression.Property(typedEntity, property), typedValue);

        return Expression.Lambda<Action<object, object?>>(assignment, entity, value).Compile();
    }
}
