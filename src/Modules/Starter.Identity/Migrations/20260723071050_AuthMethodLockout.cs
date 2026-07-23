using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Identity.Migrations
{
    /// <summary>
    /// Adds lockout state to the password credential
    /// (role-templates-and-policy-defaults.md section 4): <c>failed_attempts</c> (not
    /// null, default 0) and <c>locked_until</c> (nullable) on <c>identity.auth_methods</c>.
    /// Only the kind=password row uses them - Google-OIDC has no password credential,
    /// so it is never locked. Auto-unlock is implicit (locked_until &lt;= now), so no
    /// unlock job or index is needed.
    /// </summary>
    /// <inheritdoc />
    internal partial class AuthMethodLockout : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "failed_attempts",
                schema: "identity",
                table: "auth_methods",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "locked_until",
                schema: "identity",
                table: "auth_methods",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "failed_attempts",
                schema: "identity",
                table: "auth_methods");

            migrationBuilder.DropColumn(
                name: "locked_until",
                schema: "identity",
                table: "auth_methods");
        }
    }
}
