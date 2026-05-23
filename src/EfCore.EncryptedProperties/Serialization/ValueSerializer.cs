using System.Buffers.Binary;
using System.Text;
using EfCore.EncryptedProperties.Abstractions;
using EfCore.EncryptedProperties.Configuration;

namespace EfCore.EncryptedProperties.Serialization;

internal sealed class ValueSerializer : IValueSerializer
{
    private readonly EncryptedPropertiesOptions _options;

    public ValueSerializer()
        : this(new EncryptedPropertiesOptions())
    {
    }

    public ValueSerializer(EncryptedPropertiesOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public byte[] Serialize(object? value, Type type)
    {
        var underlyingType = Nullable.GetUnderlyingType(type);
        if (underlyingType is not null)
        {
            if (value is null)
                return [0x00];

            var inner = Serialize(value, underlyingType);
            var result = new byte[1 + inner.Length];
            result[0] = 0x01;
            inner.CopyTo(result, 1);
            return result;
        }

        if (type.IsEnum)
        {
            var enumUnderlyingType = Enum.GetUnderlyingType(type);
            var numericValue = Convert.ChangeType(value!, enumUnderlyingType);
            return Serialize(numericValue, enumUnderlyingType);
        }

        return SerializeCore(value!, type);
    }

    public object? Deserialize(byte[] data, Type type)
    {
        var underlyingType = Nullable.GetUnderlyingType(type);
        if (underlyingType is not null)
        {
            if (data.Length == 1 && data[0] == 0x00)
                return null;

            var inner = data.AsSpan(1).ToArray();
            return Deserialize(inner, underlyingType);
        }

        if (type.IsEnum)
        {
            var enumUnderlyingType = Enum.GetUnderlyingType(type);
            var numericValue = Deserialize(data, enumUnderlyingType);
            return Enum.ToObject(type, numericValue!);
        }

        return DeserializeCore(data, type);
    }

    private byte[] SerializeCore(object value, Type type)
    {
        if (type == typeof(string))
            return Encoding.UTF8.GetBytes((string)value);

        if (type == typeof(byte[]))
            return (byte[])value;

        if (type == typeof(bool))
            return [(bool)value ? (byte)0x01 : (byte)0x00];

        if (type == typeof(byte))
            return [(byte)value];

        if (type == typeof(sbyte))
            return [unchecked((byte)(sbyte)value)];

        if (type == typeof(short))
        {
            var buf = new byte[2];
            BinaryPrimitives.WriteInt16BigEndian(buf, (short)value);
            return buf;
        }

        if (type == typeof(ushort))
        {
            var buf = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(buf, (ushort)value);
            return buf;
        }

        if (type == typeof(int))
        {
            var buf = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(buf, (int)value);
            return buf;
        }

        if (type == typeof(uint))
        {
            var buf = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)value);
            return buf;
        }

        if (type == typeof(long))
        {
            var buf = new byte[8];
            BinaryPrimitives.WriteInt64BigEndian(buf, (long)value);
            return buf;
        }

        if (type == typeof(ulong))
        {
            var buf = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(buf, (ulong)value);
            return buf;
        }

        if (type == typeof(float))
        {
            var buf = new byte[4];
            BinaryPrimitives.WriteSingleBigEndian(buf, (float)value);
            return buf;
        }

        if (type == typeof(double))
        {
            var buf = new byte[8];
            BinaryPrimitives.WriteDoubleBigEndian(buf, (double)value);
            return buf;
        }

        if (type == typeof(decimal))
        {
            var bits = decimal.GetBits((decimal)value);
            var buf = new byte[16];
            for (var i = 0; i < 4; i++)
                BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(i * 4), bits[i]);
            return buf;
        }

        if (type == typeof(DateTime))
        {
            var buf = new byte[8];
            BinaryPrimitives.WriteInt64BigEndian(buf, ((DateTime)value).ToBinary());
            return buf;
        }

        if (type == typeof(DateTimeOffset))
        {
            var dto = (DateTimeOffset)value;
            var buf = new byte[10];
            BinaryPrimitives.WriteInt64BigEndian(buf, dto.DateTime.ToBinary());
            BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(8), (short)dto.Offset.TotalMinutes);
            return buf;
        }

        if (type == typeof(Guid))
            return ((Guid)value).ToByteArray();

        if (_options.TryGetValueSerializer(type, out var serializer))
            return serializer.Serialize(value);

        throw new NotSupportedException($"Type '{type}' is not supported for encryption.");
    }

    private object? DeserializeCore(byte[] data, Type type)
    {
        if (type == typeof(string))
            return Encoding.UTF8.GetString(data);

        if (type == typeof(byte[]))
            return data;

        if (type == typeof(bool))
            return data[0] != 0x00;

        if (type == typeof(byte))
            return data[0];

        if (type == typeof(sbyte))
            return unchecked((sbyte)data[0]);

        if (type == typeof(short))
            return BinaryPrimitives.ReadInt16BigEndian(data);

        if (type == typeof(ushort))
            return BinaryPrimitives.ReadUInt16BigEndian(data);

        if (type == typeof(int))
            return BinaryPrimitives.ReadInt32BigEndian(data);

        if (type == typeof(uint))
            return BinaryPrimitives.ReadUInt32BigEndian(data);

        if (type == typeof(long))
            return BinaryPrimitives.ReadInt64BigEndian(data);

        if (type == typeof(ulong))
            return BinaryPrimitives.ReadUInt64BigEndian(data);

        if (type == typeof(float))
            return BinaryPrimitives.ReadSingleBigEndian(data);

        if (type == typeof(double))
            return BinaryPrimitives.ReadDoubleBigEndian(data);

        if (type == typeof(decimal))
        {
            var bits = new int[4];
            for (var i = 0; i < 4; i++)
                bits[i] = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(i * 4));
            return new decimal(bits);
        }

        if (type == typeof(DateTime))
            return DateTime.FromBinary(BinaryPrimitives.ReadInt64BigEndian(data));

        if (type == typeof(DateTimeOffset))
        {
            var dt = DateTime.FromBinary(BinaryPrimitives.ReadInt64BigEndian(data));
            var offsetMinutes = BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(8));
            return new DateTimeOffset(dt, TimeSpan.FromMinutes(offsetMinutes));
        }

        if (type == typeof(Guid))
            return new Guid(data);

        if (_options.TryGetValueSerializer(type, out var serializer))
            return serializer.Deserialize(data);

        throw new NotSupportedException($"Type '{type}' is not supported for encryption.");
    }
}
