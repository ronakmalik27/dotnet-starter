using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <inheritdoc />
    internal partial class ScopedRbac : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "roles",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    description = table.Column<string>(type: "text", nullable: true),
                    assignable_at = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    workspace_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_roles", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "role_assignments",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    principal_type = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role_id = table.Column<Guid>(type: "uuid", nullable: false),
                    scope_type = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    scope_id = table.Column<Guid>(type: "uuid", nullable: true),
                    granted_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_role_assignments", x => x.id);
                    table.ForeignKey(
                        name: "fk_role_assignments_roles_role_id",
                        column: x => x.role_id,
                        principalSchema: "tenancy",
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "role_permissions",
                schema: "tenancy",
                columns: table => new
                {
                    role_id = table.Column<Guid>(type: "uuid", nullable: false),
                    permission = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_role_permissions", x => new { x.role_id, x.permission });
                    table.ForeignKey(
                        name: "fk_role_permissions_roles_role_id",
                        column: x => x.role_id,
                        principalSchema: "tenancy",
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_role_assignments_role_id",
                schema: "tenancy",
                table: "role_assignments",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "ix_role_assignments_tenant_scope_unique",
                schema: "tenancy",
                table: "role_assignments",
                columns: new[] { "tenant_id", "principal_type", "principal_id", "role_id" },
                unique: true,
                filter: "scope_type = 'tenant'");

            migrationBuilder.CreateIndex(
                name: "ix_role_assignments_workspace_scope_unique",
                schema: "tenancy",
                table: "role_assignments",
                columns: new[] { "tenant_id", "principal_type", "principal_id", "role_id", "scope_id" },
                unique: true,
                filter: "scope_type = 'workspace'");

            migrationBuilder.CreateIndex(
                name: "ix_roles_tenant_id_workspace_id_key",
                schema: "tenancy",
                table: "roles",
                columns: new[] { "tenant_id", "workspace_id", "key" },
                unique: true)
                .Annotation("Npgsql:NullsDistinct", false);

            // Row-level security on every new tenant-owned table: the
            // authoritative isolation boundary, the SAME fail-closed policy as
            // tenancy.memberships and tenancy.invitations (keyed on tenant_id).
            // FORCE is mandatory - the bypass (migrating) role owns the tables
            // and only BYPASSRLS lets it through; the request role is a non-owner
            // grantee, so it is bound. nullif(current_setting(...), '') maps a
            // reset-placeholder empty string back to NULL, so a no-tenant read
            // matches zero rows and a no-tenant INSERT fails WITH CHECK - never an
            // error, never a leak. role_permissions and role_assignments carry a
            // denormalized tenant_id so a raw read cannot cross tenants even
            // through the FK.
            migrationBuilder.Sql("""
                alter table tenancy.roles enable row level security;
                alter table tenancy.roles force row level security;
                create policy tenant_isolation on tenancy.roles
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

                alter table tenancy.role_permissions enable row level security;
                alter table tenancy.role_permissions force row level security;
                create policy tenant_isolation on tenancy.role_permissions
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

                alter table tenancy.role_assignments enable row level security;
                alter table tenancy.role_assignments force row level security;
                create policy tenant_isolation on tenancy.role_assignments
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                drop policy if exists tenant_isolation on tenancy.role_assignments;
                drop policy if exists tenant_isolation on tenancy.role_permissions;
                drop policy if exists tenant_isolation on tenancy.roles;
                """);

            migrationBuilder.DropTable(
                name: "role_assignments",
                schema: "tenancy");

            migrationBuilder.DropTable(
                name: "role_permissions",
                schema: "tenancy");

            migrationBuilder.DropTable(
                name: "roles",
                schema: "tenancy");
        }
    }
}
