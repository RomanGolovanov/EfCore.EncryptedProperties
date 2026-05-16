using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EfCore.EncryptedProperties.KeyManagement;

internal sealed class EncryptedPropertyKekConfiguration : IEntityTypeConfiguration<EncryptedPropertyKek>
{
    public void Configure(EntityTypeBuilder<EncryptedPropertyKek> builder)
    {
        builder.ToTable("EncryptedPropertyKeks");
        builder.HasKey(k => k.Id);
        builder.Property(k => k.Purpose).HasMaxLength(128).IsRequired();
        builder.Property(k => k.RsaKeyId).HasMaxLength(512).IsRequired();
        builder.Property(k => k.Algorithm).HasMaxLength(64).IsRequired();
        builder.Property(k => k.EncryptedKey).IsRequired();
        builder.Property(k => k.CreatedAt).IsRequired();
        builder.Property(k => k.IsActive).IsRequired();
        builder.HasIndex(k => new { k.Purpose, k.IsActive });
        builder.HasIndex(k => k.Purpose)
            .HasDatabaseName("UX_EncryptedPropertyKeks_ActivePurpose")
            .IsUnique()
            .HasFilter("[IsActive] = 1");
    }
}
