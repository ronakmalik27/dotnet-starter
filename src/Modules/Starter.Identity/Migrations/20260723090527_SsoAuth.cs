using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Identity.Migrations
{
    /// <summary>
    /// Enterprise SSO auth (sso-and-scim.md sections 2, 4): adds
    /// identity.auth_methods.issuer (the CRITICAL cross-IdP takeover fix) and splits
    /// the subject-uniqueness index by issuer - non-SSO methods keep
    /// (kind, provider_subject) unique (issuer IS NULL), SSO methods are unique on
    /// (kind, issuer, provider_subject) (issuer IS NOT NULL), so one tenant's IdP
    /// can never collide with or be matched as another's subject. Also adds
    /// identity.sso_login_states, the single-use server-side record binding an SSO
    /// authorize request to its callback (a global Identity table, no RLS).
    /// </summary>
    /// <inheritdoc />
    internal partial class SsoAuth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_auth_methods_kind_provider_subject",
                schema: "identity",
                table: "auth_methods");

            migrationBuilder.AddColumn<string>(
                name: "issuer",
                schema: "identity",
                table: "auth_methods",
                type: "character varying(2048)",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "sso_login_states",
                schema: "identity",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    state_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    nonce = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    code_verifier = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    redirect_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sso_login_states", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_auth_methods_kind_issuer_provider_subject",
                schema: "identity",
                table: "auth_methods",
                columns: new[] { "kind", "issuer", "provider_subject" },
                unique: true,
                filter: "issuer IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_auth_methods_kind_provider_subject",
                schema: "identity",
                table: "auth_methods",
                columns: new[] { "kind", "provider_subject" },
                unique: true,
                filter: "issuer IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_sso_login_states_state_hash",
                schema: "identity",
                table: "sso_login_states",
                column: "state_hash",
                unique: true,
                filter: "used_at IS NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "sso_login_states",
                schema: "identity");

            migrationBuilder.DropIndex(
                name: "ix_auth_methods_kind_issuer_provider_subject",
                schema: "identity",
                table: "auth_methods");

            migrationBuilder.DropIndex(
                name: "ix_auth_methods_kind_provider_subject",
                schema: "identity",
                table: "auth_methods");

            migrationBuilder.DropColumn(
                name: "issuer",
                schema: "identity",
                table: "auth_methods");

            migrationBuilder.CreateIndex(
                name: "ix_auth_methods_kind_provider_subject",
                schema: "identity",
                table: "auth_methods",
                columns: new[] { "kind", "provider_subject" },
                unique: true);
        }
    }
}
