using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <summary>
    /// Adds the nullable <c>template_key</c> to <c>tenancy.roles</c>
    /// (role-templates-and-policy-defaults.md section 2): the platform role template a
    /// role was SEEDED from (null for a tenant-authored role), plus a PARTIAL unique
    /// index on (tenant_id, template_key) WHERE template_key IS NOT NULL - the race
    /// backstop that makes a re-seed idempotent (a concurrent bulk-seed and provision
    /// cannot double-seed the same template into a tenant).
    /// </summary>
    /// <inheritdoc />
    internal partial class RoleTemplateKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "template_key",
                schema: "tenancy",
                table: "roles",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ux_roles_tenant_template_key",
                schema: "tenancy",
                table: "roles",
                columns: new[] { "tenant_id", "template_key" },
                unique: true,
                filter: "template_key is not null");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_roles_tenant_template_key",
                schema: "tenancy",
                table: "roles");

            migrationBuilder.DropColumn(
                name: "template_key",
                schema: "tenancy",
                table: "roles");
        }
    }
}
