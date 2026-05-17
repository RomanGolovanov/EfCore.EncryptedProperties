using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EfCore.EncryptedProperties.Metadata;

internal sealed class EncryptedPropertyModelCache
{
    private readonly ConcurrentDictionary<IModel, Lazy<EncryptedPropertyModel>> _models = new();
    private readonly ILogger<EncryptedPropertyModelCache> _logger;

    public EncryptedPropertyModelCache(ILogger<EncryptedPropertyModelCache>? logger = null)
    {
        _logger = logger ?? NullLogger<EncryptedPropertyModelCache>.Instance;
    }

    public EncryptedPropertyModel GetOrAdd(IModel model)
    {
        return _models.GetOrAdd(
            model,
            static (model, cache) => new Lazy<EncryptedPropertyModel>(
                () => cache.BuildModel(model),
                LazyThreadSafetyMode.ExecutionAndPublication),
            this).Value;
    }

    private EncryptedPropertyModel BuildModel(IModel model)
    {
        var encryptedModel = EncryptedPropertyModelBuilder.Build(model);

        _logger.LogInformation(
            EncryptedPropertiesEventIds.EncryptedPropertyModelDiscovered,
            "Discovered {EncryptedPropertyCount} encrypted properties in EF model {ModelId}.",
            encryptedModel.Properties.Count,
            RuntimeHelpers.GetHashCode(model));

        foreach (var property in encryptedModel.Properties)
        {
            _logger.LogDebug(
                EncryptedPropertiesEventIds.EncryptedPropertyDiscovered,
                "Discovered encrypted property {EntityTypeName}.{PropertyName} stored in {CiphertextPropertyName} for purpose {Purpose} using {MaterializationMode} materialization and CLR type {ClrType}.",
                property.EntityTypeName,
                property.PropertyName,
                property.CiphertextPropertyName,
                property.Purpose,
                property.Mode,
                property.ClrType.FullName ?? property.ClrType.Name);
        }

        return encryptedModel;
    }
}
