using EfCore.EncryptedProperties.Serialization;

namespace EfCore.EncryptedProperties.Tests.Serialization;

public class ValueSerializerTests
{
    private readonly ValueSerializer _serializer = new();

    [Theory]
    [InlineData("hello world")]
    [InlineData("")]
    [InlineData("Unicode: éèê 你好")]
    public void RoundTrip_String(string value)
    {
        var bytes = _serializer.Serialize(value, typeof(string));
        var result = _serializer.Deserialize(bytes, typeof(string));
        Assert.Equal(value, result);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RoundTrip_Bool(bool value)
    {
        var bytes = _serializer.Serialize(value, typeof(bool));
        var result = _serializer.Deserialize(bytes, typeof(bool));
        Assert.Equal(value, result);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(42)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void RoundTrip_Int(int value)
    {
        var bytes = _serializer.Serialize(value, typeof(int));
        var result = _serializer.Deserialize(bytes, typeof(int));
        Assert.Equal(value, result);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void RoundTrip_Long(long value)
    {
        var bytes = _serializer.Serialize(value, typeof(long));
        var result = _serializer.Deserialize(bytes, typeof(long));
        Assert.Equal(value, result);
    }

    [Theory]
    [InlineData(3.14f)]
    [InlineData(float.MaxValue)]
    [InlineData(float.MinValue)]
    public void RoundTrip_Float(float value)
    {
        var bytes = _serializer.Serialize(value, typeof(float));
        var result = _serializer.Deserialize(bytes, typeof(float));
        Assert.Equal(value, result);
    }

    [Theory]
    [InlineData(3.14159265358979)]
    [InlineData(double.MaxValue)]
    [InlineData(double.MinValue)]
    public void RoundTrip_Double(double value)
    {
        var bytes = _serializer.Serialize(value, typeof(double));
        var result = _serializer.Deserialize(bytes, typeof(double));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_Decimal()
    {
        var values = new[] { 0m, 1.23m, -999.99m, decimal.MaxValue, decimal.MinValue };
        foreach (var value in values)
        {
            var bytes = _serializer.Serialize(value, typeof(decimal));
            var result = _serializer.Deserialize(bytes, typeof(decimal));
            Assert.Equal(value, result);
        }
    }

    [Fact]
    public void RoundTrip_Guid()
    {
        var value = Guid.NewGuid();
        var bytes = _serializer.Serialize(value, typeof(Guid));
        var result = _serializer.Deserialize(bytes, typeof(Guid));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_DateTime()
    {
        var value = new DateTime(2025, 6, 15, 10, 30, 0, DateTimeKind.Utc);
        var bytes = _serializer.Serialize(value, typeof(DateTime));
        var result = _serializer.Deserialize(bytes, typeof(DateTime));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_DateTimeOffset()
    {
        var value = new DateTimeOffset(2025, 6, 15, 10, 30, 0, TimeSpan.FromHours(3));
        var bytes = _serializer.Serialize(value, typeof(DateTimeOffset));
        var result = (DateTimeOffset)_serializer.Deserialize(bytes, typeof(DateTimeOffset))!;
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_ByteArray()
    {
        var value = new byte[] { 1, 2, 3, 4, 5 };
        var bytes = _serializer.Serialize(value, typeof(byte[]));
        var result = _serializer.Deserialize(bytes, typeof(byte[]));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_Byte()
    {
        byte value = 0xAB;
        var bytes = _serializer.Serialize(value, typeof(byte));
        var result = _serializer.Deserialize(bytes, typeof(byte));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_Short()
    {
        short value = -12345;
        var bytes = _serializer.Serialize(value, typeof(short));
        var result = _serializer.Deserialize(bytes, typeof(short));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_NullableInt_WithValue()
    {
        int? value = 42;
        var bytes = _serializer.Serialize(value, typeof(int?));
        var result = _serializer.Deserialize(bytes, typeof(int?));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_NullableInt_Null()
    {
        int? value = null;
        var bytes = _serializer.Serialize(value, typeof(int?));
        var result = _serializer.Deserialize(bytes, typeof(int?));
        Assert.Null(result);
    }

    [Fact]
    public void RoundTrip_Enum()
    {
        var value = DayOfWeek.Wednesday;
        var bytes = _serializer.Serialize(value, typeof(DayOfWeek));
        var result = _serializer.Deserialize(bytes, typeof(DayOfWeek));
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_NullableEnum()
    {
        DayOfWeek? value = DayOfWeek.Friday;
        var bytes = _serializer.Serialize(value, typeof(DayOfWeek?));
        var result = _serializer.Deserialize(bytes, typeof(DayOfWeek?));
        Assert.Equal(value, result);
    }
}
