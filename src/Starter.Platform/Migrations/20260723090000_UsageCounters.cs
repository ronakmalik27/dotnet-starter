using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// Usage quotas (quotas.md sections 2, 10): the tenant-owned, RLS-enforced
    /// <c>platform.usage_counters</c> - one row per (tenant, metric, period) for the
    /// metered counter. Unlike <c>platform.plans</c> / <c>platform.feature_flags</c>
    /// (operator-owned, REVOKE'd from the request role), this is a NORMAL
    /// request-role DML table: the boot-time blanket grant covers it and there is NO
    /// REVOKE pass, so a tenant's own request increments its own counter under RLS.
    /// The <c>tenant_isolation</c> policy is the SAME fail-closed policy every other
    /// tenant-owned table uses; FORCE is mandatory because the migrating (bypass)
    /// role owns the table. Resource-count quotas need no table (they count the
    /// resource's own rows), so nothing else is added here.
    /// </summary>
    /// <inheritdoc />
    internal partial class UsageCounters : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "usage_counters",
                schema: "platform",
                columns: table => new
                {
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    metric = table.Column<string>(type: "text", nullable: false),
                    period_start = table.Column<DateOnly>(type: "date", nullable: false),
                    used = table.Column<long>(type: "bigint", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_usage_counters", x => new { x.tenant_id, x.metric, x.period_start });
                });

            // Row-level security on the tenant-owned counter (quotas.md section 2): the
            // SAME fail-closed tenant_isolation policy every other tenant-owned table
            // uses (keyed on tenant_id). FORCE is mandatory - the migrating (bypass)
            // role owns the table and only BYPASSRLS lets it through, so the request
            // role (a non-owner grantee) is bound. nullif(current_setting(...), '')
            // maps a reset-placeholder empty string back to NULL, so a no-tenant read
            // matches zero rows and a no-tenant INSERT fails WITH CHECK - never an
            // error, never a leak.
            migrationBuilder.Sql("""
                alter table platform.usage_counters enable row level security;
                alter table platform.usage_counters force row level security;
                create policy tenant_isolation on platform.usage_counters
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on platform.usage_counters;");

            migrationBuilder.DropTable(
                name: "usage_counters",
                schema: "platform");
        }
    }
}
