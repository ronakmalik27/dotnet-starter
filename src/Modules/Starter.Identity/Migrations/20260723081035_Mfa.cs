using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Identity.Migrations
{
    /// <summary>
    /// Adds the MFA / TOTP tables (mfa-totp.md section 2), both global-user
    /// (no tenant_id, no RLS): <c>identity.mfa_credentials</c> (one row per
    /// user, the encrypted TOTP secret plus confirmed/replay/lockout state) and
    /// <c>identity.mfa_recovery_codes</c> (the one-time, SHA-256-hashed
    /// lost-authenticator codes). Additive and removable: dropping both tables
    /// reverts login to the single-step flow (section 9).
    /// </summary>
    /// <inheritdoc />
    internal partial class Mfa : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "mfa_credentials",
                schema: "identity",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    secret_encrypted = table.Column<string>(type: "text", nullable: false),
                    pending_secret_encrypted = table.Column<string>(type: "text", nullable: true),
                    confirmed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_step = table.Column<long>(type: "bigint", nullable: true),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    locked_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mfa_credentials", x => x.user_id);
                    table.ForeignKey(
                        name: "fk_mfa_credentials_users_user_id",
                        column: x => x.user_id,
                        principalSchema: "identity",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "mfa_recovery_codes",
                schema: "identity",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    code_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mfa_recovery_codes", x => x.id);
                    table.ForeignKey(
                        name: "fk_mfa_recovery_codes_users_user_id",
                        column: x => x.user_id,
                        principalSchema: "identity",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_mfa_recovery_codes_user_id_code_hash",
                schema: "identity",
                table: "mfa_recovery_codes",
                columns: new[] { "user_id", "code_hash" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "mfa_credentials",
                schema: "identity");

            migrationBuilder.DropTable(
                name: "mfa_recovery_codes",
                schema: "identity");
        }
    }
}
