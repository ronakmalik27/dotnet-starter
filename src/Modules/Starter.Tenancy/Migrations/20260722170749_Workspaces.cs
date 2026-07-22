using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <inheritdoc />
    internal partial class Workspaces : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "workspaces",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    slug = table.Column<string>(type: "citext", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_workspaces", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_workspaces_tenant_id_slug",
                schema: "tenancy",
                table: "workspaces",
                columns: new[] { "tenant_id", "slug" },
                unique: true);

            // Row-level security on the new tenant-owned table: the authoritative
            // isolation boundary, the SAME fail-closed policy as every other
            // tenancy table (keyed on tenant_id). A workspace is an authorization
            // scope INSIDE the tenant (multi-tenancy.md section 12), so it adds NO
            // second GUC - the tenant policy alone bounds it, and one tenant can
            // never see another's workspaces. FORCE is mandatory: the migrating
            // (bypass) role owns the table and only BYPASSRLS lets it through; the
            // request role is a non-owner grantee, so it is bound.
            // nullif(current_setting(...), '') maps a reset-placeholder empty
            // string back to NULL, so a no-tenant read matches zero rows and a
            // no-tenant INSERT fails WITH CHECK - never an error, never a leak.
            migrationBuilder.Sql("""
                alter table tenancy.workspaces enable row level security;
                alter table tenancy.workspaces force row level security;
                create policy tenant_isolation on tenancy.workspaces
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.workspaces;");

            migrationBuilder.DropTable(
                name: "workspaces",
                schema: "tenancy");
        }
    }
}
