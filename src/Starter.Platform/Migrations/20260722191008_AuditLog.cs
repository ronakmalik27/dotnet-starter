using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// The audit log (audit-log.md sections 3, 4): the per-tenant audit projection
    /// <c>platform.audit_log</c> (tenant-owned, RLS-enforced - the FIRST and only
    /// RLS table in the platform schema) plus the null-tenant
    /// <c>platform.platform_audit_log</c> (no RLS). The append-only / bypass-only
    /// posture (the request role loses UPDATE/DELETE on audit_log and ALL on
    /// platform_audit_log) is the boot-time REVOKE pass in TenantRoleProvisioner,
    /// re-run every boot after the blanket grant, not DDL here.
    /// </summary>
    /// <inheritdoc />
    internal partial class AuditLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_log",
                schema: "platform",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    recorded_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    action = table.Column<string>(type: "text", nullable: false),
                    actor_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    entity_id = table.Column<Guid>(type: "uuid", nullable: true),
                    summary = table.Column<string>(type: "text", nullable: false),
                    data = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_log", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "platform_audit_log",
                schema: "platform",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    recorded_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    action = table.Column<string>(type: "text", nullable: false),
                    actor_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    subject_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    summary = table.Column<string>(type: "text", nullable: false),
                    data = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_platform_audit_log", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_audit_log_tenant_action_occurred",
                schema: "platform",
                table: "audit_log",
                columns: new[] { "tenant_id", "action", "occurred_at" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "ix_audit_log_tenant_actor_occurred",
                schema: "platform",
                table: "audit_log",
                columns: new[] { "tenant_id", "actor_user_id", "occurred_at" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "ix_audit_log_tenant_occurred",
                schema: "platform",
                table: "audit_log",
                columns: new[] { "tenant_id", "occurred_at" },
                descending: new[] { false, true });

            // Row-level security on platform.audit_log: the tenant audit log is
            // tenant-owned, so a tenant admin reading it is bound by the same
            // authoritative boundary as every other tenant read (audit-log.md
            // sections 3, 9). This is the FIRST RLS table in the platform schema, a
            // deliberate, documented exception - the SAME fail-closed policy as
            // every tenancy table (keyed on tenant_id). FORCE is mandatory: the
            // migrating (bypass) role owns the table and only BYPASSRLS lets it
            // through, so the request role (a non-owner grantee) is bound.
            // nullif(current_setting(...), '') maps a reset-placeholder empty string
            // back to NULL, so a no-tenant read matches zero rows and a no-tenant
            // INSERT fails WITH CHECK - never an error, never a leak.
            //
            // platform.platform_audit_log gets NO RLS: it is null-tenant and read
            // only behind RequirePlatformAdmin, consistent with every other
            // platform table.
            migrationBuilder.Sql("""
                alter table platform.audit_log enable row level security;
                alter table platform.audit_log force row level security;
                create policy tenant_isolation on platform.audit_log
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on platform.audit_log;");

            migrationBuilder.DropTable(
                name: "audit_log",
                schema: "platform");

            migrationBuilder.DropTable(
                name: "platform_audit_log",
                schema: "platform");
        }
    }
}
