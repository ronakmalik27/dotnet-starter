using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <summary>
    /// Enterprise SSO configuration (sso-and-scim.md section 2): tenancy.sso_configs
    /// (one per-tenant OIDC IdP, tenant_id as the primary key) and
    /// tenancy.sso_domain_claims (the routing domains, one row per domain with a
    /// GLOBAL unique index on the normalized citext domain so a domain is claimable
    /// by at most one tenant). Both are tenant-owned and carry the same fail-closed
    /// RLS policy as every other tenancy table, keyed on tenant_id: the migrating
    /// (bypass) role owns the tables and only BYPASSRLS lets the SSO config reader
    /// cross the boundary, while the request role is bound. The global domain index
    /// is enforced across tenants regardless of RLS visibility, so a duplicate claim
    /// is a constraint violation the request role cannot silently miss.
    /// </summary>
    /// <inheritdoc />
    internal partial class Sso : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "sso_configs",
                schema: "tenancy",
                columns: table => new
                {
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    issuer = table.Column<string>(type: "text", nullable: false),
                    client_id = table.Column<string>(type: "text", nullable: false),
                    client_secret_encrypted = table.Column<string>(type: "text", nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sso_configs", x => x.tenant_id);
                });

            migrationBuilder.CreateTable(
                name: "sso_domain_claims",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    domain = table.Column<string>(type: "citext", nullable: false),
                    verified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sso_domain_claims", x => x.id);
                });

            // The GLOBAL unique index on the normalized domain (sso-and-scim.md
            // section 2): a domain is claimable by at most ONE tenant. citext makes
            // the match case-insensitive; the uniqueness spans every tenant (RLS
            // governs visibility, not this constraint), so a second tenant's claim
            // for the same domain is rejected even though it cannot see the first
            // tenant's row - credential-phishing routing is a constraint violation,
            // not a policy hope.
            migrationBuilder.CreateIndex(
                name: "ix_sso_domain_claims_domain_unique",
                schema: "tenancy",
                table: "sso_domain_claims",
                column: "domain",
                unique: true);

            // The admin list is a tenant-scoped read.
            migrationBuilder.CreateIndex(
                name: "ix_sso_domain_claims_tenant_id",
                schema: "tenancy",
                table: "sso_domain_claims",
                column: "tenant_id");

            // Row-level security on the two new tenant-owned tables: the
            // authoritative isolation boundary, the SAME fail-closed policy as every
            // other tenancy table (keyed on tenant_id). FORCE is mandatory so the
            // migrating (bypass) owner role is bound on the request path; the SSO
            // config reader runs on the BYPASSRLS role precisely because the
            // pre-tenant lookups (domain routing, config read at callback) cross the
            // boundary. nullif(current_setting(...), '') maps a reset-placeholder
            // empty string back to NULL, so a no-tenant read matches zero rows and a
            // no-tenant INSERT fails WITH CHECK - never an error, never a leak.
            migrationBuilder.Sql("""
                alter table tenancy.sso_configs enable row level security;
                alter table tenancy.sso_configs force row level security;
                create policy tenant_isolation on tenancy.sso_configs
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

                alter table tenancy.sso_domain_claims enable row level security;
                alter table tenancy.sso_domain_claims force row level security;
                create policy tenant_isolation on tenancy.sso_domain_claims
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.sso_domain_claims;");
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.sso_configs;");

            migrationBuilder.DropTable(
                name: "sso_configs",
                schema: "tenancy");

            migrationBuilder.DropTable(
                name: "sso_domain_claims",
                schema: "tenancy");
        }
    }
}
