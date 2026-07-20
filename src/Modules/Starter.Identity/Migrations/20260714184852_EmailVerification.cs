using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Identity.Migrations
{
    /// <inheritdoc />
    internal partial class EmailVerification : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "email_verified_at",
                schema: "identity",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "verification_deadline_at",
                schema: "identity",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "one_time_tokens",
                schema: "identity",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    payload = table.Column<string>(type: "jsonb", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_one_time_tokens", x => x.id);
                    table.ForeignKey(
                        name: "fk_one_time_tokens_users_user_id",
                        column: x => x.user_id,
                        principalSchema: "identity",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_one_time_tokens_token_hash",
                schema: "identity",
                table: "one_time_tokens",
                column: "token_hash",
                unique: true,
                filter: "used_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_one_time_tokens_user_id_purpose_created_at",
                schema: "identity",
                table: "one_time_tokens",
                columns: new[] { "user_id", "purpose", "created_at" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "one_time_tokens",
                schema: "identity");

            migrationBuilder.DropColumn(
                name: "email_verified_at",
                schema: "identity",
                table: "users");

            migrationBuilder.DropColumn(
                name: "verification_deadline_at",
                schema: "identity",
                table: "users");
        }
    }
}
