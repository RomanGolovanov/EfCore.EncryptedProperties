using EfCore.EncryptedProperties.Extensions;
using Microsoft.EntityFrameworkCore;

namespace EfCore.EncryptedProperties.Samples;

public sealed class SampleDbContext : DbContext
{
    public SampleDbContext(DbContextOptions<SampleDbContext> options) : base(options) { }

    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
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

            entity.Property(e => e.LoyaltyPoints)
                .IsEncrypted(options =>
                {
                    options.KeyPurpose = "loyalty";
                });
        });
    }
}
