using EfCore.EncryptedProperties.Extensions;
using Microsoft.EntityFrameworkCore;

namespace EfCore.EncryptedProperties.ApiSample;

public sealed class ApiSampleDbContext : DbContext
{
    public ApiSampleDbContext(DbContextOptions<ApiSampleDbContext> options) : base(options) { }

    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.UseEncryptedPropertiesKekStorage();

        modelBuilder.Entity<Customer>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.Property(e => e.Email)
                .IsEncrypted();

            entity.Property(e => e.SecretNotes)
                .IsEncrypted(options =>
                {
                    options.KeyPurpose = "notes";
                });
        });
    }
}
