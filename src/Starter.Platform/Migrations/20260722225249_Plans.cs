using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// The plan catalogue (billing-and-entitlements.md sections 2, 11):
    /// <c>platform.plans</c>, a no-RLS operator-owned table (the platform_admins
    /// shape), plus the exactly-one-default partial unique index on
    /// <c>is_default</c>. It seeds ONE row - <c>free</c>, the default - with
    /// <c>features</c> and <c>permissions</c> as SQL NULL (both unrestricted) and
    /// <c>limits = { "seatLimit": 5 }</c>. The NULLs are load-bearing: NULL means
    /// the plan restricts NOTHING, whereas an empty array <c>{}</c> would strip
    /// every feature and grantable permission from every tenant at once - the exact
    /// opposite. So a freshly-provisioned tenant resolves to "all features, all
    /// permissions, 5 seats" and nothing that ships today changes behavior. The
    /// boot-time REVOKE of write on the table from the request role is the
    /// TenantRoleProvisioner grant pass (re-run every boot after the blanket grant),
    /// not DDL here.
    /// </summary>
    /// <inheritdoc />
    internal partial class Plans : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "plans",
                schema: "platform",
                columns: table => new
                {
                    key = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    features = table.Column<string[]>(type: "text[]", nullable: true),
                    permissions = table.Column<string[]>(type: "text[]", nullable: true),
                    limits = table.Column<string>(type: "jsonb", nullable: false),
                    is_default = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_plans", x => x.key);
                });

            migrationBuilder.CreateIndex(
                name: "ux_plans_is_default",
                schema: "platform",
                table: "plans",
                column: "is_default",
                unique: true,
                filter: "is_default");

            // Seed the default `free` plan. features and permissions MUST be SQL
            // NULL (unrestricted), NEVER an empty array {} - by the semantics above
            // they are opposites, and {} would deny everything to every tenant. Raw
            // SQL (not InsertData) so the NULLs are unambiguous.
            migrationBuilder.Sql("""
                insert into platform.plans (key, name, features, permissions, limits, is_default, created_at, updated_at)
                values ('free', 'Free', null, null, '{"seatLimit": 5}'::jsonb, true, now(), now());
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "plans",
                schema: "platform");
        }
    }
}
