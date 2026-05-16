using EfCore.EncryptedProperties.Extensions;
using Microsoft.EntityFrameworkCore;

namespace EfCore.EncryptedProperties.Tests.KeyManagement;

public sealed class EncryptedPropertyKekConfigurationTests
{
    [Fact]
    public void KekStorageModel_ConfiguresRsaKeyIdLength()
    {
        using var context = CreateContext();
        var entityType = context.Model.GetEntityTypes()
            .Single(e => e.GetTableName() == "EncryptedPropertyKeks");

        var rsaKeyId = entityType.FindProperty("RsaKeyId");

        Assert.NotNull(rsaKeyId);
        Assert.Equal(512, rsaKeyId!.GetMaxLength());
    }

    [Fact]
    public void KekStorageModel_ConfiguresUniqueActivePurposeIndex()
    {
        using var context = CreateContext();
        var entityType = context.Model.GetEntityTypes()
            .Single(e => e.GetTableName() == "EncryptedPropertyKeks");

        var index = entityType.GetIndexes()
            .Single(i => i.GetDatabaseName() == "UX_EncryptedPropertyKeks_ActivePurpose");

        Assert.True(index.IsUnique);
        Assert.Equal("[IsActive] = 1", index.GetFilter());
    }

    private static KekModelContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<KekModelContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new KekModelContext(options);
    }

    private sealed class KekModelContext : DbContext
    {
        public KekModelContext(DbContextOptions<KekModelContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.UseEncryptedPropertiesKekStorage();
        }
    }
}
