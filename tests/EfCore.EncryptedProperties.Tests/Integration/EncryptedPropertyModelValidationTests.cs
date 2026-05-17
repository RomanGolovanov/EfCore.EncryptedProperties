using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Extensions;
using EfCore.EncryptedProperties.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Tests.Integration;

public class EncryptedPropertyModelValidationTests
{
    [Fact]
    public void ModelFinalization_UnsupportedTransparentReferenceType_ThrowsClearError()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => FinalizeModel<UnsupportedUriDbContext>());

        Assert.Contains(nameof(UnsupportedUriEntity.Website), ex.Message);
        Assert.Contains(typeof(Uri).FullName!, ex.Message);
        Assert.Contains("unsupported CLR type", ex.Message);
    }

    [Fact]
    public void ModelFinalization_UnsupportedCustomReferenceType_ThrowsClearError()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => FinalizeModel<UnsupportedCustomTypeDbContext>());

        Assert.Contains(nameof(UnsupportedCustomTypeEntity.Secret), ex.Message);
        Assert.Contains(typeof(CustomSecret).FullName!, ex.Message);
        Assert.Contains("unsupported CLR type", ex.Message);
    }

    [Fact]
    public void ModelFinalization_UnsupportedLazyInnerType_ThrowsClearError()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => FinalizeModel<UnsupportedLazyUriDbContext>());

        Assert.Contains(nameof(UnsupportedLazyUriEntity.Website), ex.Message);
        Assert.Contains(typeof(Uri).FullName!, ex.Message);
        Assert.Contains("unsupported CLR type", ex.Message);
    }

    [Fact]
    public void ModelFinalization_LazyMaterializationOnNonEncryptedValue_ThrowsClearError()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => FinalizeModel<InvalidLazyMaterializationDbContext>());

        Assert.Contains(nameof(InvalidMaterializationEntity.Email), ex.Message);
        Assert.Contains("must be EncryptedValue<T>", ex.Message);
    }

    [Fact]
    public void ModelFinalization_DecryptOnReadMaterializationOnEncryptedValue_ThrowsClearError()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => FinalizeModel<InvalidDecryptOnReadMaterializationDbContext>());

        Assert.Contains(nameof(InvalidEncryptedValueMaterializationEntity.Secret), ex.Message);
        Assert.Contains("must be configured for lazy materialization", ex.Message);
    }

    [Fact]
    public void ModelFinalization_InvalidMaterialization_ThrowsClearError()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => FinalizeModel<InvalidMaterializationModeDbContext>());

        Assert.Contains(nameof(InvalidMaterializationEntity.Email), ex.Message);
        Assert.Contains("invalid materialization mode", ex.Message);
        Assert.Contains("DecryptOnRead", ex.Message);
        Assert.Contains("Lazy", ex.Message);
    }

    [Fact]
    public async Task NullableSupportedEncryptedProperties_SaveNullsAndRoundTrip()
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddEncryptedPropertiesForTesting();
        services.AddDbContext<NullableSupportedDbContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(dbName);
            builder.UseEncryptedPropertiesForTesting(sp);
        });

        await using var provider = services.BuildServiceProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<NullableSupportedDbContext>();
            context.Entities.Add(new NullableSupportedEntity
            {
                Id = id,
                Email = null,
                Score = null,
                Token = null,
                FavoriteDay = null
            });
            await context.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<NullableSupportedDbContext>();
            var entity = await context.Entities.FindAsync(id);

            Assert.NotNull(entity);
            Assert.Null(entity!.Email);
            Assert.Null(entity.Score);
            Assert.Null(entity.Token);
            Assert.Null(entity.FavoriteDay);
        }
    }

    private static void FinalizeModel<TContext>()
        where TContext : DbContext
    {
        var services = new ServiceCollection();
        services.AddEncryptedPropertiesForTesting();
        services.AddDbContext<TContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(Guid.NewGuid().ToString());
            builder.UseEncryptedPropertiesForTesting(sp);
        });

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        _ = scope.ServiceProvider.GetRequiredService<TContext>().Model;
    }

    private sealed class UnsupportedUriDbContext : DbContext
    {
        public UnsupportedUriDbContext(DbContextOptions<UnsupportedUriDbContext> options) : base(options)
        {
        }

        public DbSet<UnsupportedUriEntity> Entities => Set<UnsupportedUriEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UnsupportedUriEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Website).IsEncrypted();
            });
        }
    }

    private sealed class UnsupportedCustomTypeDbContext : DbContext
    {
        public UnsupportedCustomTypeDbContext(DbContextOptions<UnsupportedCustomTypeDbContext> options) : base(options)
        {
        }

        public DbSet<UnsupportedCustomTypeEntity> Entities => Set<UnsupportedCustomTypeEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UnsupportedCustomTypeEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Secret).IsEncrypted();
            });
        }
    }

    private sealed class UnsupportedLazyUriDbContext : DbContext
    {
        public UnsupportedLazyUriDbContext(DbContextOptions<UnsupportedLazyUriDbContext> options) : base(options)
        {
        }

        public DbSet<UnsupportedLazyUriEntity> Entities => Set<UnsupportedLazyUriEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UnsupportedLazyUriEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Website).IsEncrypted();
            });
        }
    }

    private sealed class InvalidLazyMaterializationDbContext : DbContext
    {
        public InvalidLazyMaterializationDbContext(DbContextOptions<InvalidLazyMaterializationDbContext> options)
            : base(options)
        {
        }

        public DbSet<InvalidMaterializationEntity> Entities => Set<InvalidMaterializationEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<InvalidMaterializationEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email)
                    .IsEncrypted()
                    .HasAnnotation(EncryptedPropertyAnnotations.Materialization, "Lazy");
            });
        }
    }

    private sealed class InvalidDecryptOnReadMaterializationDbContext : DbContext
    {
        public InvalidDecryptOnReadMaterializationDbContext(
            DbContextOptions<InvalidDecryptOnReadMaterializationDbContext> options)
            : base(options)
        {
        }

        public DbSet<InvalidEncryptedValueMaterializationEntity> Entities => Set<InvalidEncryptedValueMaterializationEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<InvalidEncryptedValueMaterializationEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Secret)
                    .IsEncrypted()
                    .HasAnnotation(EncryptedPropertyAnnotations.Materialization, "DecryptOnRead");
            });
        }
    }

    private sealed class InvalidMaterializationModeDbContext : DbContext
    {
        public InvalidMaterializationModeDbContext(DbContextOptions<InvalidMaterializationModeDbContext> options)
            : base(options)
        {
        }

        public DbSet<InvalidMaterializationEntity> Entities => Set<InvalidMaterializationEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<InvalidMaterializationEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email)
                    .IsEncrypted()
                    .HasAnnotation(EncryptedPropertyAnnotations.Materialization, "Invalid");
            });
        }
    }

    private sealed class NullableSupportedDbContext : DbContext
    {
        public NullableSupportedDbContext(DbContextOptions<NullableSupportedDbContext> options) : base(options)
        {
        }

        public DbSet<NullableSupportedEntity> Entities => Set<NullableSupportedEntity>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<NullableSupportedEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsEncrypted();
                entity.Property(e => e.Score).IsEncrypted();
                entity.Property(e => e.Token).IsEncrypted();
                entity.Property(e => e.FavoriteDay).IsEncrypted();
            });
        }
    }

    private sealed class UnsupportedUriEntity
    {
        public Guid Id { get; set; }
        public Uri Website { get; set; } = new("https://example.com");
    }

    private sealed class UnsupportedCustomTypeEntity
    {
        public Guid Id { get; set; }
        public CustomSecret Secret { get; set; } = new();
    }

    private sealed class UnsupportedLazyUriEntity
    {
        public Guid Id { get; set; }
        public EncryptedValue<Uri> Website { get; set; } = default!;
    }

    private sealed class InvalidMaterializationEntity
    {
        public Guid Id { get; set; }
        public string Email { get; set; } = string.Empty;
    }

    private sealed class InvalidEncryptedValueMaterializationEntity
    {
        public Guid Id { get; set; }
        public EncryptedValue<string> Secret { get; set; } = default!;
    }

    private sealed class NullableSupportedEntity
    {
        public Guid Id { get; set; }
        public string? Email { get; set; }
        public int? Score { get; set; }
        public byte[]? Token { get; set; }
        public DayOfWeek? FavoriteDay { get; set; }
    }

    private sealed class CustomSecret
    {
        public string Value { get; set; } = string.Empty;
    }
}
