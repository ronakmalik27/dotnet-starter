using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Data;

namespace Starter.Identity;

/// <summary>
/// The identity module's context: owns the identity schema and
/// nothing else (doc 07 section 2). The schema binding and conventions
/// come from ModuleDbContext; users, auth_methods, and sessions landed
/// with #33 and one_time_tokens with #34 (doc 07 section 4) - the
/// remaining identity tables join with their stories.
/// </summary>
internal sealed class IdentityDbContext(DbContextOptions<IdentityDbContext> options)
    : ModuleDbContext(options, SchemaName)
{
    internal const string SchemaName = "identity";

    public DbSet<User> Users => Set<User>();

    public DbSet<AuthMethod> AuthMethods => Set<AuthMethod>();

    public DbSet<Session> Sessions => Set<Session>();

    public DbSet<OneTimeToken> OneTimeTokens => Set<OneTimeToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // citext: case-insensitive email uniqueness in the column type
        // itself (doc 07 section 4), so no lookup can forget to normalize.
        modelBuilder.HasPostgresExtension("citext");

        modelBuilder.Entity<User>(user =>
        {
            user.Property(u => u.Email).HasColumnType("citext");
            user.HasIndex(u => u.Email).IsUnique();
            user.Property(u => u.Status).HasMaxLength(32);
        });

        modelBuilder.Entity<AuthMethod>(method =>
        {
            method.Property(m => m.Kind).HasMaxLength(32);
            // The FR-AUTH-15 list shape: one row per method, at most one
            // of each kind per user, and an OIDC subject binds to exactly
            // one account (doc 07 section 4).
            method.HasIndex(m => new { m.UserId, m.Kind }).IsUnique();
            method.HasIndex(m => new { m.Kind, m.ProviderSubject }).IsUnique();
            // Google subs are numeric strings today, but the OIDC spec caps
            // sub at 255 ASCII characters - size to the spec, not the
            // current issuer behavior.
            method.Property(m => m.ProviderSubject).HasMaxLength(255);
            method.HasOne<User>().WithMany().HasForeignKey(m => m.UserId);
        });

        modelBuilder.Entity<OneTimeToken>(token =>
        {
            token.Property(t => t.Purpose).HasMaxLength(32);
            token.Property(t => t.TokenHash).HasMaxLength(64);
            token.Property(t => t.Payload).HasColumnType("jsonb");
            // The redemption lookup (doc 07 section 12: "(token_hash)
            // where used_at is null"); unique within the live set so two
            // live tokens can never share a hash.
            token.HasIndex(t => t.TokenHash).IsUnique().HasFilter("used_at IS NULL");
            // The doc 10 4.6 resend guard counts an account's recent
            // issuances per purpose; this is that query's index.
            token.HasIndex(t => new { t.UserId, t.Purpose, t.CreatedAt });
            token.HasOne<User>().WithMany().HasForeignKey(t => t.UserId);
        });

        modelBuilder.Entity<Session>(session =>
        {
            // The refresh lookup path (doc 07 section 12: every query has
            // its index): token hash to row, then family for revocation.
            session.HasIndex(s => s.RefreshHash).IsUnique();
            session.HasIndex(s => s.FamilyId);
            session.Property(s => s.RefreshHash).HasMaxLength(64);
            session.Property(s => s.DeviceLabel).HasMaxLength(200);
            session.Property(s => s.Ip).HasMaxLength(64);
            session.HasOne<User>().WithMany().HasForeignKey(s => s.UserId);
        });
    }
}
