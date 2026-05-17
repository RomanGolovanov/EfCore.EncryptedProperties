using EfCore.EncryptedProperties.Configuration;
using EfCore.EncryptedProperties.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.EncryptedProperties.Tests.Integration;

public class DataAnnotationTests
{
    private static ServiceProvider CreateProvider()
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddEncryptedPropertiesForTesting();
        services.AddDbContext<TestDbContext>((sp, builder) =>
        {
            builder.UseInMemoryDatabase(dbName);
            builder.UseEncryptedPropertiesForTesting(sp);
        });
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task EncryptedAttribute_ConfiguresTransparentAndLazyProperties()
    {
        await using var provider = CreateProvider();
        var id = Guid.NewGuid();

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var entityType = ctx.Model.FindEntityType(typeof(AnnotatedCustomer))!;
            var emailStorage = entityType.FindProperty("__EncryptedProperties_Email");
            var notesStorage = entityType.FindProperty("__EncryptedProperties_SecretNotes");

            Assert.Null(entityType.FindProperty(nameof(AnnotatedCustomer.Email)));
            Assert.Null(entityType.FindProperty(nameof(AnnotatedCustomer.SecretNotes)));
            Assert.NotNull(emailStorage);
            Assert.NotNull(notesStorage);
            Assert.Equal("email", emailStorage!.FindAnnotation(EncryptedPropertyAnnotations.KeyPurpose)?.Value);
            Assert.Equal("DecryptOnRead", emailStorage.FindAnnotation(EncryptedPropertyAnnotations.Materialization)?.Value);
            Assert.Equal("Lazy", notesStorage!.FindAnnotation(EncryptedPropertyAnnotations.Materialization)?.Value);

            ctx.Customers.Add(new AnnotatedCustomer
            {
                Id = id,
                Email = "annotated@example.com",
                SecretNotes = "annotation secret",
                Name = "Annotated User"
            });

            await ctx.SaveChangesAsync();
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            var customer = await ctx.Customers.FindAsync(id);

            Assert.NotNull(customer);
            Assert.Equal("annotated@example.com", customer!.Email);
            Assert.Equal("Annotated User", customer.Name);
            Assert.Equal("annotation secret", await customer.SecretNotes.GetDecryptedValueAsync());
        }
    }

    private sealed class TestDbContext : DbContext
    {
        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options)
        {
        }

        public DbSet<AnnotatedCustomer> Customers => Set<AnnotatedCustomer>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AnnotatedCustomer>(entity =>
            {
                entity.HasKey(e => e.Id);
            });
        }
    }

    private sealed class AnnotatedCustomer
    {
        public Guid Id { get; set; }

        [Encrypted("email")]
        public string Email { get; set; } = string.Empty;

        [Encrypted]
        public EncryptedValue<string> SecretNotes { get; set; } = default!;

        public string Name { get; set; } = string.Empty;
    }
}
