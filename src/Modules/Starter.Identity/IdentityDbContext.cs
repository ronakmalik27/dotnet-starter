using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;

namespace Starter.Identity;

/// <summary>
/// The identity module's context: owns the identity schema and
/// nothing else. The schema binding and conventions
/// come from ModuleDbContext; users, auth_methods, sessions, and
/// one_time_tokens landed first - the
/// remaining identity tables join with their stories. Users are global, so
/// nothing here is tenant-owned; the context carries an ITenantContext only to
/// fit the one module-context shape.
/// </summary>
internal sealed class IdentityDbContext(DbContextOptions<IdentityDbContext> options, ITenantContext tenantContext)
    : ModuleDbContext(options, SchemaName, tenantContext)
{
    internal const string SchemaName = "identity";

    public DbSet<User> Users => Set<User>();

    public DbSet<AuthMethod> AuthMethods => Set<AuthMethod>();

    public DbSet<Session> Sessions => Set<Session>();

    public DbSet<OneTimeToken> OneTimeTokens => Set<OneTimeToken>();

    public DbSet<MfaCredential> MfaCredentials => Set<MfaCredential>();

    public DbSet<MfaRecoveryCode> MfaRecoveryCodes => Set<MfaRecoveryCode>();

    public DbSet<SsoLoginState> SsoLoginStates => Set<SsoLoginState>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // citext: case-insensitive email uniqueness in the column type
        // itself, so no lookup can forget to normalize.
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
            // The list shape: one row per method, at most one
            // of each kind per user, and an OIDC subject binds to exactly
            // one account.
            method.HasIndex(m => new { m.UserId, m.Kind }).IsUnique();
            // The subject-uniqueness index is SPLIT by whether the row carries an
            // issuer (sso-and-scim.md section 2, the CRITICAL cross-IdP takeover fix):
            //  - non-SSO methods (issuer IS NULL: password with a null subject, and
            //    google under its single globally-trusted issuer) keep the original
            //    two-column (kind, provider_subject) uniqueness;
            //  - SSO methods (issuer IS NOT NULL) are unique on (kind, issuer,
            //    provider_subject), so one tenant's IdP can never collide with - or
            //    be matched as - another's subject, and two tenants' IdPs assigning
            //    the same sub to different people no longer fail provisioning.
            method.HasIndex(m => new { m.Kind, m.ProviderSubject })
                .IsUnique()
                .HasFilter("issuer IS NULL");
            method.HasIndex(m => new { m.Kind, m.Issuer, m.ProviderSubject })
                .IsUnique()
                .HasFilter("issuer IS NOT NULL")
                .HasDatabaseName("ix_auth_methods_kind_issuer_provider_subject");
            // Google subs are numeric strings today, but the OIDC spec caps
            // sub at 255 ASCII characters - size to the spec, not the
            // current issuer behavior. The issuer is an https URL (authority).
            method.Property(m => m.ProviderSubject).HasMaxLength(255);
            method.Property(m => m.Issuer).HasMaxLength(2048);
            // Lockout state on the password credential
            // (role-templates-and-policy-defaults.md section 4): failed_attempts
            // defaults to 0, locked_until is null until the threshold is crossed.
            method.Property(m => m.FailedAttempts).HasDefaultValue(0);
            method.HasOne<User>().WithMany().HasForeignKey(m => m.UserId);
        });

        modelBuilder.Entity<OneTimeToken>(token =>
        {
            token.Property(t => t.Purpose).HasMaxLength(32);
            token.Property(t => t.TokenHash).HasMaxLength(64);
            token.Property(t => t.Payload).HasColumnType("jsonb");
            // The redemption lookup ("(token_hash)
            // where used_at is null"); unique within the live set so two
            // live tokens can never share a hash.
            token.HasIndex(t => t.TokenHash).IsUnique().HasFilter("used_at IS NULL");
            // The resend guard counts an account's recent
            // issuances per purpose; this is that query's index.
            token.HasIndex(t => new { t.UserId, t.Purpose, t.CreatedAt });
            token.HasOne<User>().WithMany().HasForeignKey(t => t.UserId);
        });

        modelBuilder.Entity<Session>(session =>
        {
            // The refresh lookup path (every query has
            // its index): token hash to row, then family for revocation.
            session.HasIndex(s => s.RefreshHash).IsUnique();
            session.HasIndex(s => s.FamilyId);
            session.Property(s => s.RefreshHash).HasMaxLength(64);
            session.Property(s => s.DeviceLabel).HasMaxLength(200);
            session.Property(s => s.Ip).HasMaxLength(64);
            session.HasOne<User>().WithMany().HasForeignKey(s => s.UserId);
        });

        modelBuilder.Entity<MfaCredential>(mfa =>
        {
            // One enrollment per user: the user id IS the primary key
            // (global-user credential, like the password - no tenant, no RLS).
            mfa.HasKey(m => m.UserId);
            mfa.Property(m => m.FailedAttempts).HasDefaultValue(0);
            mfa.HasOne<User>().WithMany().HasForeignKey(m => m.UserId);
        });

        modelBuilder.Entity<MfaRecoveryCode>(code =>
        {
            code.Property(c => c.CodeHash).HasMaxLength(64);
            // The verify lookup path: the caller's live codes by hash.
            code.HasIndex(c => new { c.UserId, c.CodeHash });
            code.HasOne<User>().WithMany().HasForeignKey(c => c.UserId);
        });

        modelBuilder.Entity<SsoLoginState>(state =>
        {
            state.Property(s => s.StateHash).HasMaxLength(64);
            state.Property(s => s.Nonce).HasMaxLength(128);
            state.Property(s => s.CodeVerifier).HasMaxLength(128);
            state.Property(s => s.RedirectUri).HasMaxLength(2048);
            // The callback lookup keys on the state hash; unique within the live
            // (unconsumed) set so two live states can never share a hash - the same
            // shape as one_time_tokens.
            state.HasIndex(s => s.StateHash).IsUnique().HasFilter("used_at IS NULL");
            // A global Identity table like sessions/users: no tenant ownership and no
            // RLS. The tenant_id it carries is data (the ONLY tenant source at
            // callback), not an ownership discriminator, so no FK and no query filter.
        });
    }
}
