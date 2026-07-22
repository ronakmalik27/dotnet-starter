using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// Outbound webhooks (webhooks.md sections 2, 12): the tenant-owned, RLS-enforced
    /// <c>platform.webhook_endpoints</c> and <c>platform.webhook_deliveries</c> tables,
    /// with the unique <c>(endpoint_id, event_id)</c> fan-out idempotency key and the
    /// partial <c>(next_attempt_at) where status = 'pending'</c> claim index. Both are
    /// RLS-bound (the second and third RLS tables in the platform schema, after
    /// <c>audit_log</c>) so a tenant admin only ever sees its own endpoints and deliveries;
    /// the worker drains them on the BYPASSRLS role.
    /// </summary>
    /// <inheritdoc />
    internal partial class Webhooks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "webhook_deliveries",
                schema: "platform",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    event_id = table.Column<Guid>(type: "uuid", nullable: false),
                    event_type = table.Column<string>(type: "text", nullable: false),
                    payload = table.Column<string>(type: "jsonb", nullable: false),
                    status = table.Column<string>(type: "text", nullable: false),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    next_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    delivered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    dead_lettered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_response_status = table.Column<int>(type: "integer", nullable: true),
                    last_error = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_webhook_deliveries", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "webhook_endpoints",
                schema: "platform",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    url = table.Column<string>(type: "text", nullable: false),
                    description = table.Column<string>(type: "text", nullable: false),
                    event_types = table.Column<string[]>(type: "text[]", nullable: false),
                    signing_secret_encrypted = table.Column<string>(type: "text", nullable: false),
                    secret_prefix = table.Column<string>(type: "text", nullable: false),
                    disabled_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_webhook_endpoints", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_webhook_deliveries_claim",
                schema: "platform",
                table: "webhook_deliveries",
                column: "next_attempt_at",
                filter: "status = 'pending'");

            migrationBuilder.CreateIndex(
                name: "ix_webhook_deliveries_tenant_endpoint_created",
                schema: "platform",
                table: "webhook_deliveries",
                columns: new[] { "tenant_id", "endpoint_id", "created_at" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "ux_webhook_deliveries_endpoint_event",
                schema: "platform",
                table: "webhook_deliveries",
                columns: new[] { "endpoint_id", "event_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_webhook_endpoints_tenant",
                schema: "platform",
                table: "webhook_endpoints",
                column: "tenant_id");

            // Row-level security on the two webhook tables (webhooks.md section 1): both
            // are tenant-owned, so a tenant admin reading its endpoints or deliveries is
            // bound by the same authoritative boundary as every other tenant read - the
            // SAME fail-closed tenant_isolation policy as every tenancy table (keyed on
            // tenant_id). FORCE is mandatory: the migrating (bypass) role owns the tables
            // and only BYPASSRLS lets it through, so the request role (a non-owner grantee)
            // is bound; the delivery worker drains cross-tenant precisely because it runs
            // on the BYPASSRLS role. nullif(current_setting(...), '') maps a
            // reset-placeholder empty string back to NULL, so a no-tenant read matches zero
            // rows and a no-tenant INSERT fails WITH CHECK - never an error, never a leak.
            migrationBuilder.Sql("""
                alter table platform.webhook_endpoints enable row level security;
                alter table platform.webhook_endpoints force row level security;
                create policy tenant_isolation on platform.webhook_endpoints
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

                alter table platform.webhook_deliveries enable row level security;
                alter table platform.webhook_deliveries force row level security;
                create policy tenant_isolation on platform.webhook_deliveries
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on platform.webhook_deliveries;");
            migrationBuilder.Sql("drop policy if exists tenant_isolation on platform.webhook_endpoints;");

            migrationBuilder.DropTable(
                name: "webhook_deliveries",
                schema: "platform");

            migrationBuilder.DropTable(
                name: "webhook_endpoints",
                schema: "platform");
        }
    }
}
