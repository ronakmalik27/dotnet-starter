using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <inheritdoc />
    internal partial class Invitations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "invitations",
                schema: "tenancy",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    email = table.Column<string>(type: "citext", nullable: false),
                    role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    accepted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    invited_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_invitations", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_invitations_tenant_id_email",
                schema: "tenancy",
                table: "invitations",
                columns: new[] { "tenant_id", "email" });

            migrationBuilder.CreateIndex(
                name: "ix_invitations_token_hash",
                schema: "tenancy",
                table: "invitations",
                column: "token_hash");

            // Row-level security: the authoritative isolation boundary, the SAME
            // fail-closed policy as tenancy.memberships (keyed on tenant_id). FORCE
            // is mandatory - the table is owned by the migrating (bypass) role, and
            // only BYPASSRLS lets it through; the request role is a non-owner
            // grantee, so it is bound. nullif(current_setting(...), '') maps a
            // reset-placeholder empty string back to NULL, so a no-tenant read
            // matches zero rows and a no-tenant INSERT fails WITH CHECK - never an
            // error, never a leak. The accept path reads by token_hash on the
            // BYPASSRLS role, which is exempt (the invitee holds no tid yet).
            migrationBuilder.Sql("""
                alter table tenancy.invitations enable row level security;
                alter table tenancy.invitations force row level security;
                create policy tenant_isolation on tenancy.invitations
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on tenancy.invitations;");

            migrationBuilder.DropTable(
                name: "invitations",
                schema: "tenancy");
        }
    }
}
