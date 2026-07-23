using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// The install-wide policy-defaults singleton
    /// (role-templates-and-policy-defaults.md section 3):
    /// <c>platform.policy_defaults</c>, a no-RLS operator-owned table like the plan /
    /// feature-flag catalogues, but the FIRST SINGLETON shape here - the primary key
    /// is a <c>one_row</c> boolean fixed true with a <c>check (one_row)</c>, so exactly
    /// one row can ever exist (no demote-race, no "which is active"; called out because
    /// it diverges from the multi-row + is_default catalogues). It SEEDS the one row
    /// with today's constant values (min length 10, 15-minute access token, 30-day
    /// refresh family, 10 attempts, 15-minute lock), so nothing changes behavior on
    /// ship - the defaults ARE the current constants. The boot-time REVOKE of write
    /// from the request role is the TenantRoleProvisioner grant pass, not DDL here.
    /// </summary>
    /// <inheritdoc />
    internal partial class PolicyDefaults : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "policy_defaults",
                schema: "platform",
                columns: table => new
                {
                    one_row = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    password_min_length = table.Column<int>(type: "integer", nullable: false),
                    access_token_lifetime_seconds = table.Column<int>(type: "integer", nullable: false),
                    refresh_lifetime_seconds = table.Column<int>(type: "integer", nullable: false),
                    lockout_max_attempts = table.Column<int>(type: "integer", nullable: false),
                    lockout_duration_seconds = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_policy_defaults", x => x.one_row);
                    table.CheckConstraint("ck_policy_defaults_one_row", "one_row");
                });

            // Seed the single row with today's constants (PolicyDefaults.BuiltIn), so a
            // fresh install behaves exactly as before the feature. one_row defaults to
            // true (the singleton guarantee), so it is not named here.
            migrationBuilder.Sql("""
                insert into platform.policy_defaults
                  (password_min_length, access_token_lifetime_seconds, refresh_lifetime_seconds,
                   lockout_max_attempts, lockout_duration_seconds)
                values (10, 900, 2592000, 10, 900);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "policy_defaults",
                schema: "platform");
        }
    }
}
