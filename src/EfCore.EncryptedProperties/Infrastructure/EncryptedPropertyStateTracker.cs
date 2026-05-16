using System.Runtime.CompilerServices;
using EfCore.EncryptedProperties.Metadata;

namespace EfCore.EncryptedProperties.Infrastructure;

internal sealed class EncryptedPropertyStateTracker
{
    private readonly ConditionalWeakTable<object, Dictionary<string, EncryptedPropertySnapshot>> _snapshots = new();

    public void Track(
        object entity,
        EncryptedPropertyDescriptor descriptor,
        object? plaintext,
        string? payload)
    {
        var snapshots = _snapshots.GetOrCreateValue(entity);
        snapshots[descriptor.PropertyName] = new EncryptedPropertySnapshot(CloneSnapshotValue(plaintext), payload);
    }

    public bool TryGet(
        object entity,
        EncryptedPropertyDescriptor descriptor,
        out EncryptedPropertySnapshot snapshot)
    {
        if (_snapshots.TryGetValue(entity, out var snapshots)
            && snapshots.TryGetValue(descriptor.PropertyName, out snapshot))
        {
            return true;
        }

        snapshot = default;
        return false;
    }

    public static bool ValueEquals(object? left, object? right)
    {
        if (ReferenceEquals(left, right))
            return true;

        if (left is null || right is null)
            return false;

        if (left is byte[] leftBytes && right is byte[] rightBytes)
            return leftBytes.SequenceEqual(rightBytes);

        return left.Equals(right);
    }

    private static object? CloneSnapshotValue(object? value)
    {
        return value is byte[] bytes
            ? bytes.ToArray()
            : value;
    }
}

internal readonly record struct EncryptedPropertySnapshot(object? Plaintext, string? Payload);
