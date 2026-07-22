using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <summary>
    /// Increment 7 schema (multi-tenancy.md sections 14, 16, 17): teams and
    /// team_members (a team is a tenant-owned principal that can hold grants), plus
    /// the scope-aware-invitation columns on tenancy.invitations (workspace_id +
    /// role_id, the workspace-scoped role to grant on accept).
    /// </summary>
    /// <inheritdoc />
    internal partial class Teams : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Scope-aware invitations (multi-tenancy.md section 16): an invite may
            // also target a workspace and a custom role there. Both columns are
            // nullable - null for a plain tenant invite, set together for "invited
            // straight into a role on a workspace". The invitations table is
            // already tenant-owned under RLS (the Invitations migration), so these
            // scalar additions inherit that policy with no further SQL. They are
            // referenced by value only (no FK), so the accept path can read them by
            // raw SQL on the bypass source before any tenant is bound.
            migrationBuilder.AddColumn<Guid>(
                name: "role_id",
                schema: "tenancy",
                table: "invitations",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "workspace_id",
                schema: "tenancy",
                table: "invitations",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "teams",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    slug = table.Column<string>(type: "citext", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_teams", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "team_members",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    team_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_team_members", x => x.id);
                    // The team's memberships cascade with it (intra-schema FK); a
                    // team delete removes them without leaving orphan rows.
                    table.ForeignKey(
                        name: "fk_team_members_teams_team_id",
                        column: x => x.team_id,
                        principalSchema: "tenancy",
                        principalTable: "teams",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_team_members_team_id_user_id",
                schema: "tenancy",
                table: "team_members",
                columns: new[] { "team_id", "user_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_teams_tenant_id_slug",
                schema: "tenancy",
                table: "teams",
                columns: new[] { "tenant_id", "slug" },
                unique: true);

            // Row-level security on the new tenant-owned tables: the authoritative
            // isolation boundary, the SAME fail-closed policy as every other
            // tenancy table (keyed on tenant_id). A team is a principal that can
            // hold grants INSIDE the tenant (multi-tenancy.md sections 14, 17), so
            // it adds NO second GUC - the tenant policy alone bounds it, and one
            // tenant can never see another's teams or team members. FORCE is
            // mandatory: the migrating (bypass) role owns the tables and only
            // BYPASSRLS lets it through; the request role is a non-owner grantee,
            // so it is bound. nullif(current_setting(...), '') maps a
            // reset-placeholder empty string back to NULL, so a no-tenant read
            // matches zero rows and a no-tenant INSERT fails WITH CHECK - never an
            // error, never a leak. team_members carries a denormalized tenant_id so
            // a raw read cannot cross tenants even through the FK.
            migrationBuilder.Sql("""
                alter table tenancy.teams enable row level security;
                alter table tenancy.teams force row level security;
                create policy tenant_isolation on tenancy.teams
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

                alter table tenancy.team_members enable row level security;
                alter table tenancy.team_members force row level security;
                create policy tenant_isolation on tenancy.team_members
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                drop policy if exists tenant_isolation on tenancy.team_members;
                drop policy if exists tenant_isolation on tenancy.teams;
                """);

            migrationBuilder.DropTable(
                name: "team_members",
                schema: "tenancy");

            migrationBuilder.DropTable(
                name: "teams",
                schema: "tenancy");

            migrationBuilder.DropColumn(
                name: "role_id",
                schema: "tenancy",
                table: "invitations");

            migrationBuilder.DropColumn(
                name: "workspace_id",
                schema: "tenancy",
                table: "invitations");
        }
    }
}
