using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// Feature flags (feature-flags.md sections 2, 10): the no-RLS operator-owned
    /// <c>platform.feature_flags</c> catalogue (the platform_admins / plans shape),
    /// plus the tenant-owned, RLS-enforced <c>platform.feature_flag_overrides</c>. The
    /// unique <c>(tenant_id, flag_key, scope_type, scope_id)</c> index uses NULLS NOT
    /// DISTINCT (the roles-catalogue idiom, NOT the role_assignments two-partial-index
    /// shape), so a tenant-scope override (scope_id NULL) is unique per flag and a
    /// PUT-as-upsert works when scope_id is NULL. The catalogue is seeded EMPTY (flags
    /// fail closed - there is nothing to gate until an operator defines one). The
    /// request-role write REVOKE on <c>platform.feature_flags</c> is added to the
    /// boot-time TenantRoleProvisioner grant pass (after the blanket grant, like plans
    /// / audit_log), NOT the EF migration DDL.
    /// </summary>
    /// <inheritdoc />
    internal partial class FeatureFlags : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "feature_flag_overrides",
                schema: "platform",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    flag_key = table.Column<string>(type: "text", nullable: false),
                    scope_type = table.Column<string>(type: "text", nullable: false),
                    scope_id = table.Column<Guid>(type: "uuid", nullable: true),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    set_by = table.Column<Guid>(type: "uuid", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_feature_flag_overrides", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "feature_flags",
                schema: "platform",
                columns: table => new
                {
                    key = table.Column<string>(type: "text", nullable: false),
                    description = table.Column<string>(type: "text", nullable: false),
                    default_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    rollout_percentage = table.Column<int>(type: "integer", nullable: true),
                    tenant_overridable = table.Column<bool>(type: "boolean", nullable: false),
                    archived_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_feature_flags", x => x.key);
                });

            migrationBuilder.CreateIndex(
                name: "ux_feature_flag_overrides_tenant_flag_scope",
                schema: "platform",
                table: "feature_flag_overrides",
                columns: new[] { "tenant_id", "flag_key", "scope_type", "scope_id" },
                unique: true)
                .Annotation("Npgsql:NullsDistinct", false);

            // Row-level security on the tenant-owned overrides table (feature-flags.md
            // section 2): the SAME fail-closed tenant_isolation policy every other
            // tenant-owned table uses (keyed on tenant_id). FORCE is mandatory - the
            // migrating (bypass) role owns the table and only BYPASSRLS lets it
            // through, so the request role (a non-owner grantee) is bound.
            // nullif(current_setting(...), '') maps a reset-placeholder empty string
            // back to NULL, so a no-tenant read matches zero rows and a no-tenant
            // INSERT fails WITH CHECK - never an error, never a leak. The
            // feature_flags catalogue is NOT tenant-owned (no RLS), like plans.
            migrationBuilder.Sql("""
                alter table platform.feature_flag_overrides enable row level security;
                alter table platform.feature_flag_overrides force row level security;
                create policy tenant_isolation on platform.feature_flag_overrides
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on platform.feature_flag_overrides;");

            migrationBuilder.DropTable(
                name: "feature_flag_overrides",
                schema: "platform");

            migrationBuilder.DropTable(
                name: "feature_flags",
                schema: "platform");
        }
    }
}
