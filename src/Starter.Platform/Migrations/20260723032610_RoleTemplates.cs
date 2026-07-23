using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// The role-template catalogue (role-templates-and-policy-defaults.md section 2):
    /// <c>platform.role_templates</c>, a no-RLS operator-owned table (the plans /
    /// platform_admins shape). Unlike the plan catalogue's NULL-means-unrestricted
    /// arrays, <c>permissions</c> and <c>assignable_scopes</c> are NOT-NULL text[] -
    /// a template names an EXACT set. It seeds nothing (a template is a deliberate
    /// operator act; there is nothing to seed until one is defined). The boot-time
    /// REVOKE of write on the table from the request role is the TenantRoleProvisioner
    /// grant pass, not DDL here.
    /// </summary>
    /// <inheritdoc />
    internal partial class RoleTemplates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "role_templates",
                schema: "platform",
                columns: table => new
                {
                    key = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    description = table.Column<string>(type: "text", nullable: false),
                    permissions = table.Column<string[]>(type: "text[]", nullable: false),
                    assignable_scopes = table.Column<string[]>(type: "text[]", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_role_templates", x => x.key);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "role_templates",
                schema: "platform");
        }
    }
}
