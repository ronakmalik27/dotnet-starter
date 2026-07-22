using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <summary>
    /// Service accounts and API keys (service-accounts.md sections 5, 11):
    /// tenancy.service_accounts, a tenant-owned principal that authenticates with a
    /// hashed API key and carries scoped grants, not a membership. The key_hash
    /// index is GLOBAL and unique (the resolve is tenant-less); the tenant_id index
    /// serves the admin list; RLS is the isolation boundary for every request-path
    /// read and write.
    /// </summary>
    /// <inheritdoc />
    internal partial class ServiceAccounts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "service_accounts",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    key_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    key_prefix = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_service_accounts", x => x.id);
                });

            // The lookup key is the SHA-256 hex of the raw key, GLOBALLY unique: the
            // resolve is tenant-less (a request has no tid until the key resolves
            // one), so the unique index spans every tenant. RLS governs visibility,
            // not this constraint, so cross-tenant uniqueness is fine.
            migrationBuilder.CreateIndex(
                name: "ix_service_accounts_key_hash_unique",
                schema: "tenancy",
                table: "service_accounts",
                column: "key_hash",
                unique: true);

            // The admin list is a tenant-scoped read.
            migrationBuilder.CreateIndex(
                name: "ix_service_accounts_tenant_id",
                schema: "tenancy",
                table: "service_accounts",
                column: "tenant_id");

            // Row-level security on the new tenant-owned table: the authoritative
            // isolation boundary, the SAME fail-closed policy as every other
            // tenancy table (keyed on tenant_id). A service account is a principal
            // that holds grants INSIDE the tenant (service-accounts.md sections 4,
            // 5), so it adds NO second GUC - the tenant policy alone bounds every
            // request-path read and write, and one tenant can never see another's
            // service accounts. FORCE is mandatory: the migrating (bypass) role owns
            // the table and only BYPASSRLS lets it through (the api-key resolve runs
            // on that role precisely because the tenant-less lookup crosses the
            // boundary); the request role is a non-owner grantee, so it is bound.
            // nullif(current_setting(...), '') maps a reset-placeholder empty string
            // back to NULL, so a no-tenant read matches zero rows and a no-tenant
            // INSERT fails WITH CHECK - never an error, never a leak.
            migrationBuilder.Sql("""
                alter table tenancy.service_accounts enable row level security;
                alter table tenancy.service_accounts force row level security;
                create policy tenant_isolation on tenancy.service_accounts
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.service_accounts;");

            migrationBuilder.DropTable(
                name: "service_accounts",
                schema: "tenancy");
        }
    }
}
