using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <summary>
    /// SCIM 2.0 provisioning (sso-and-scim.md section 5): tenancy.scim_tokens (the
    /// per-tenant SCIM bearer credential, hashed, with a GLOBAL unique index on
    /// token_hash so the tenant-less resolve keys on it) plus a nullable
    /// scim_external_id column on tenancy.memberships (the IdP's per-member externalId,
    /// round-tripped on GET/PUT). scim_tokens is tenant-owned and carries the same
    /// fail-closed RLS policy as every other tenancy table, keyed on tenant_id: the
    /// migrating (bypass) role owns the table and only BYPASSRLS lets the token resolver
    /// cross the boundary (a scim_ bearer holds no tid until it resolves one), while the
    /// request role is bound. The global token_hash index is enforced across tenants
    /// regardless of RLS visibility, so a hash collides at most once system-wide.
    /// </summary>
    /// <inheritdoc />
    internal partial class Scim : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "scim_external_id",
                schema: "tenancy",
                table: "memberships",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "scim_tokens",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    token_prefix = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scim_tokens", x => x.id);
                });

            // The admin list is a tenant-scoped read.
            migrationBuilder.CreateIndex(
                name: "ix_scim_tokens_tenant_id",
                schema: "tenancy",
                table: "scim_tokens",
                column: "tenant_id");

            // The GLOBAL unique index on token_hash (sso-and-scim.md section 5): the
            // resolve is tenant-less (a request has no tid until the token resolves it),
            // so the lookup keys on the hash alone. RLS governs visibility, not this
            // constraint, so cross-tenant uniqueness is fine (the same shape as
            // service_accounts.key_hash).
            migrationBuilder.CreateIndex(
                name: "ix_scim_tokens_token_hash_unique",
                schema: "tenancy",
                table: "scim_tokens",
                column: "token_hash",
                unique: true);

            // Row-level security on the new tenant-owned table: the authoritative
            // isolation boundary, the SAME fail-closed policy as every other tenancy
            // table (keyed on tenant_id). FORCE is mandatory so the migrating (bypass)
            // owner role is bound on the request path; the token resolver runs on the
            // BYPASSRLS role precisely because the pre-tenant lookup (a scim_ bearer has
            // no tid yet) crosses the boundary. nullif(current_setting(...), '') maps a
            // reset-placeholder empty string back to NULL, so a no-tenant read matches
            // zero rows and a no-tenant INSERT fails WITH CHECK - never an error, never
            // a leak.
            migrationBuilder.Sql("""
                alter table tenancy.scim_tokens enable row level security;
                alter table tenancy.scim_tokens force row level security;
                create policy tenant_isolation on tenancy.scim_tokens
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.scim_tokens;");

            migrationBuilder.DropTable(
                name: "scim_tokens",
                schema: "tenancy");

            migrationBuilder.DropColumn(
                name: "scim_external_id",
                schema: "tenancy",
                table: "memberships");
        }
    }
}
