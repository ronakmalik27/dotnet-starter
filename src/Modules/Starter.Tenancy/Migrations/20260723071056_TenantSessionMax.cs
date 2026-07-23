using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <summary>
    /// Adds the nullable <c>session_max_seconds</c> to <c>tenancy.tenants</c>
    /// (role-templates-and-policy-defaults.md section 5): a tenant-set tid-token
    /// lifetime override. Null means the tenant inherits the platform default; a value
    /// (validated on write to be no longer than the platform access-token lifetime)
    /// TIGHTENS the tenant's own session, and the tid mint issues
    /// <c>min(platform default, override)</c>. The one coherent tenant override in the
    /// global-user model.
    /// </summary>
    /// <inheritdoc />
    internal partial class TenantSessionMax : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "session_max_seconds",
                schema: "tenancy",
                table: "tenants",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "session_max_seconds",
                schema: "tenancy",
                table: "tenants");
        }
    }
}
