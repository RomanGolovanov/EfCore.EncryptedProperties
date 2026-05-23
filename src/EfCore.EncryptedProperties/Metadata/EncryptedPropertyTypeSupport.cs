namespace EfCore.EncryptedProperties.Metadata;

internal static class EncryptedPropertyTypeSupport
{
    public const string DecryptOnReadMaterialization = "DecryptOnRead";
    public const string LazyMaterialization = "Lazy";

    public static bool IsEncryptedValueType(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(EncryptedValue<>);
    }

    public static bool IsSupportedPlaintextType(Type type)
    {
        return IsBuiltInPlaintextType(type);
    }

    public static bool IsSupportedPlaintextType(
        Type type,
        IReadOnlyCollection<Type> customValueSerializerTypes)
    {
        if (IsBuiltInPlaintextType(type))
            return true;

        var serializerType = Nullable.GetUnderlyingType(type) ?? type;
        return customValueSerializerTypes.Contains(serializerType);
    }

    public static bool IsBuiltInPlaintextType(Type type)
    {
        var nullableType = Nullable.GetUnderlyingType(type);
        if (nullableType is not null)
        {
            return nullableType.IsEnum
                ? IsSupportedNonNullablePlaintextType(Enum.GetUnderlyingType(nullableType))
                : IsSupportedNonNullablePlaintextType(nullableType);
        }

        if (type.IsEnum)
            return IsSupportedNonNullablePlaintextType(Enum.GetUnderlyingType(type));

        return type == typeof(string)
            || type == typeof(byte[])
            || IsSupportedNonNullablePlaintextType(type);
    }

    public static string SupportedTypesDescription =>
        "string, byte[], bool, numeric primitive types, decimal, DateTime, DateTimeOffset, Guid, enums, and nullable value-type variants";

    public static string SupportedTypesDescriptionWithCustomSerializers =>
        SupportedTypesDescription + ", or types registered with WithValueSerializer<TValue>()";

    private static bool IsSupportedNonNullablePlaintextType(Type type)
    {
        return type == typeof(bool)
            || type == typeof(byte)
            || type == typeof(sbyte)
            || type == typeof(short)
            || type == typeof(ushort)
            || type == typeof(int)
            || type == typeof(uint)
            || type == typeof(long)
            || type == typeof(ulong)
            || type == typeof(float)
            || type == typeof(double)
            || type == typeof(decimal)
            || type == typeof(DateTime)
            || type == typeof(DateTimeOffset)
            || type == typeof(Guid);
    }
}
