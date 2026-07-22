using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <inheritdoc />
    internal partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "tenancy");

            migrationBuilder.AlterDatabase()
                .Annotation("Npgsql:PostgresExtension:citext", ",,");

            migrationBuilder.CreateTable(
                name: "memberships",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    invited_by = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_memberships", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "tenants",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    slug = table.Column<string>(type: "citext", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    plan = table.Column<string>(type: "text", nullable: true),
                    seat_limit = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_tenants", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_memberships_tenant_id_user_id",
                schema: "tenancy",
                table: "memberships",
                columns: new[] { "tenant_id", "user_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_tenants_slug",
                schema: "tenancy",
                table: "tenants",
                column: "slug",
                unique: true);

            // Row-level security: the authoritative isolation boundary, the same
            // fail-closed policy as sample.notes. FORCE is mandatory - the tables
            // are owned by the migrating (bypass) role, and only BYPASSRLS lets
            // it through; a normal owner would otherwise silently skip the
            // policy. The request role is a non-owner grantee, so it is bound.
            //
            // nullif(current_setting('app.current_tenant', true), '') is
            // load-bearing for fail-closed: once the GUC has been set on a pooled
            // connection its reset placeholder reverts to the EMPTY STRING (not
            // NULL), and ''::uuid would raise 22P02. nullif maps '' back to NULL,
            // so a no-tenant read matches zero rows and a no-tenant INSERT fails
            // WITH CHECK - never an error, never a leak.
            //
            // The two tables key on different columns. Memberships are ordinary
            // tenant-owned rows keyed on tenant_id. A tenant row's OWN id IS the
            // discriminator (a tenant is visible only under its own id), so its
            // policy keys on id - there is no tenant_id column on tenants.
            EnableTenantIsolation(migrationBuilder, "memberships", "tenant_id");
            EnableTenantIsolation(migrationBuilder, "tenants", "id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.tenants;");
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.memberships;");

            migrationBuilder.DropTable(
                name: "memberships",
                schema: "tenancy");

            migrationBuilder.DropTable(
                name: "tenants",
                schema: "tenancy");
        }

        private static void EnableTenantIsolation(
            MigrationBuilder migrationBuilder, string table, string discriminator)
        {
            migrationBuilder.Sql($"""
                alter table tenancy.{table} enable row level security;
                alter table tenancy.{table} force row level security;
                create policy tenant_isolation on tenancy.{table}
                  using      ({discriminator} = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check ({discriminator} = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }
    }
}
