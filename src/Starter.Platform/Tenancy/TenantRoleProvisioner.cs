using Npgsql;

namespace Starter.Platform.Tenancy;

/// <summary>
/// Provisions the two Postgres roles that make row-level security real, from a
/// single privileged (admin) connection the composition root already has.
/// <list type="bullet">
///   <item><b>Request role</b> (<see cref="RequestRole"/>): non-superuser,
///   <c>NOBYPASSRLS</c>. Every request-scoped and consumer path connects as
///   this role, so RLS binds it. It is a grantee of the tenant tables, so it
///   is subject to the policy regardless of FORCE.</item>
///   <item><b>Bypass role</b> (<see cref="BypassRole"/>): non-superuser,
///   <c>BYPASSRLS</c>. Owns the tables (it runs the migrations) and crosses
///   tenants for the escape-hatch data source. <c>BYPASSRLS</c> is why FORCE
///   ROW LEVEL SECURITY on an owned table still lets it through.</item>
/// </list>
/// <para>
/// Why here and not only in docker-compose or an init script: this keeps the
/// mechanism identical for the integration Testcontainer (which starts as a
/// superuser), the compose stack, and any host - one code path, provisioned on
/// first boot. The two roles derive their username from the admin connection
/// and REUSE the admin credential's password: that adds no new secret to the
/// repo (the admin password already lives in config or the secret store), and
/// it is deterministic across instances, so a scaled-out fleet (the outbox
/// dispatcher elects a leader across instances) never fights over a per-boot
/// random password. The admin connection is used ONLY to provision; it is
/// never registered for request-scoped resolution.
/// </para>
/// </summary>
public sealed class TenantRoleProvisioner
{
    /// <summary>The RLS-bound role every request and consumer connects as.</summary>
    public const string RequestRole = "starter_app";

    /// <summary>The BYPASSRLS role for migrations, bootstrap, and cross-tenant jobs.</summary>
    public const string BypassRole = "starter_bypass";

    private readonly string _adminConnectionString;
    private readonly string _databaseName;
    private readonly string _rolePassword;

    private TenantRoleProvisioner(string adminConnectionString)
    {
        var admin = new NpgsqlConnectionStringBuilder(adminConnectionString);
        _adminConnectionString = adminConnectionString;
        _databaseName = admin.Database
            ?? throw new ArgumentException(
                "The admin connection string must name a database.", nameof(adminConnectionString));
        _rolePassword = admin.Password
            ?? throw new ArgumentException(
                "The admin connection string must carry a password.", nameof(adminConnectionString));

        RequestConnectionString = WithRole(admin, RequestRole, _rolePassword);
        BypassConnectionString = WithRole(admin, BypassRole, _rolePassword);
    }

    /// <summary>The request-role (RLS-bound) connection string. Register as the normal data source.</summary>
    public string RequestConnectionString { get; }

    /// <summary>The bypass-role (RLS-exempt) connection string. Migrations and the bypass data source.</summary>
    public string BypassConnectionString { get; }

    /// <summary>
    /// Derives the two role connection strings from the admin connection by
    /// swapping the username (the password carries over unchanged, as do host,
    /// database, and pooling options).
    /// </summary>
    public static TenantRoleProvisioner FromAdminConnection(string adminConnectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adminConnectionString);
        return new TenantRoleProvisioner(adminConnectionString);
    }

    /// <summary>
    /// Creates the two roles if absent, (re)sets their attributes and password,
    /// and grants database-level rights: CONNECT to both, CREATE to the bypass
    /// role so it can create the schemas and own the tables through migrations.
    /// Idempotent (safe on every boot). Runs on the admin connection.
    /// </summary>
    public async Task EnsureRolesAsync(CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(_adminConnectionString);
        await connection.OpenAsync(cancellationToken);

        await EnsureRoleAsync(connection, RequestRole, bypassRls: false, cancellationToken);
        await EnsureRoleAsync(connection, BypassRole, bypassRls: true, cancellationToken);

        var database = QuoteIdentifier(_databaseName);
        await ExecuteAsync(
            connection,
            $"grant connect on database {database} to {RequestRole}, {BypassRole};"
            + $"grant create on database {database} to {BypassRole};",
            cancellationToken);
    }

    /// <summary>
    /// Grants the request role the rights to work under RLS on the given
    /// schemas: USAGE on the schema, DML on every table, and the sequence
    /// rights a table might need. Run AFTER migrations, since the bypass role
    /// owns the freshly-created tables. Idempotent.
    /// <para>
    /// It then runs the audit-log REVOKE pass (audit-log.md section 8), AFTER the
    /// blanket grant so it is never silently undone: the append-only tenant audit
    /// log <c>platform.audit_log</c> loses UPDATE and DELETE (select + insert
    /// only), and the null-tenant <c>platform.platform_audit_log</c> loses every
    /// privilege (the request role can neither see nor forge it). So an attacker
    /// who reaches request-role SQL still cannot edit or erase the tenant audit
    /// trail, and cannot touch the platform trail at all. This is
    /// DB-enforced-append-only, part of this increment's build sequence, not an
    /// optional hardening. Guarded on the platform schema being present, and
    /// idempotent (REVOKE of an absent privilege is a no-op).
    /// </para>
    /// </summary>
    public async Task GrantRequestRolePrivilegesAsync(
        IReadOnlyCollection<string> schemas,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(schemas);
        if (schemas.Count == 0)
        {
            return;
        }

        var schemaList = string.Join(", ", schemas.Select(QuoteIdentifier));

        await using var connection = new NpgsqlConnection(_adminConnectionString);
        await connection.OpenAsync(cancellationToken);
        await ExecuteAsync(
            connection,
            $"grant usage on schema {schemaList} to {RequestRole};"
            + $"grant select, insert, update, delete on all tables in schema {schemaList} to {RequestRole};"
            + $"grant usage, select on all sequences in schema {schemaList} to {RequestRole};",
            cancellationToken);

        // The audit-log append-only / bypass-only REVOKE pass, run in the same
        // provisioner step every boot, AFTER the blanket grant above. Only when
        // the platform schema is present (it always is on a real boot); the two
        // audit tables live in it.
        if (schemas.Contains(Starter.Platform.Data.PlatformDbContext.SchemaName, StringComparer.Ordinal))
        {
            await ExecuteAsync(
                connection,
                $"revoke update, delete on platform.audit_log from {RequestRole};"
                + $"revoke all on platform.platform_audit_log from {RequestRole};"
                // The plan catalogue is operator-managed (billing-and-entitlements.md
                // section 2): the request role may only READ it (entitlement
                // resolution), never write it. Only the bypass role (the super-admin
                // path) creates or edits plans, so a tenant can never edit the
                // catalogue. REVOKE of an absent grant is a no-op, so this is
                // idempotent and safe if the plans table has not been created yet.
                + $"revoke insert, update, delete on platform.plans from {RequestRole};"
                // The feature-flag catalogue is operator-managed the same way
                // (feature-flags.md section 2): the request role may only READ it (the
                // evaluator resolves against it), never write it. Only the bypass role
                // (the super-admin path) creates or edits flags. The overrides table
                // stays normal request-role DML (a tenant admin writes its own,
                // RLS-scoped). Idempotent (REVOKE of an absent grant is a no-op).
                + $"revoke insert, update, delete on platform.feature_flags from {RequestRole};",
                cancellationToken);
        }
    }

    private async Task EnsureRoleAsync(
        NpgsqlConnection connection,
        string role,
        bool bypassRls,
        CancellationToken cancellationToken)
    {
        // CREATE ROLE has no IF NOT EXISTS; the DO block makes it idempotent.
        // The ALTER always runs so the attributes and password converge. ALTER
        // ROLE .. PASSWORD takes a literal, not a bind parameter, so the
        // password is emitted as an escaped SQL string literal (single quotes
        // doubled; standard_conforming_strings is on by default).
        var bypass = bypassRls ? "bypassrls" : "nobypassrls";
        var password = QuoteLiteral(_rolePassword);
        await ExecuteAsync(
            connection,
            $"""
            do $$
            begin
              if not exists (select 1 from pg_roles where rolname = '{role}') then
                create role {role} login;
              end if;
            end $$;
            alter role {role} with login nosuperuser nocreatedb {bypass} password {password};
            """,
            cancellationToken);
    }

    private static async Task ExecuteAsync(
        NpgsqlConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string WithRole(NpgsqlConnectionStringBuilder admin, string role, string password)
    {
        var builder = new NpgsqlConnectionStringBuilder(admin.ConnectionString)
        {
            Username = role,
            Password = password,
        };
        return builder.ConnectionString;
    }

    private static string QuoteIdentifier(string identifier) =>
        "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    private static string QuoteLiteral(string literal) =>
        "'" + literal.Replace("'", "''", StringComparison.Ordinal) + "'";
}
