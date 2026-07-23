using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <summary>
    /// In-app notifications (in-app-notifications.md section 2): the tenant-owned,
    /// RLS-enforced <c>platform.notifications</c> - one row per (recipient, source
    /// event) inbox item, projected from a curated subset of domain events. Like
    /// <c>platform.usage_counters</c> (and unlike the operator-owned
    /// <c>platform.plans</c> / <c>platform.feature_flags</c>) this is a NORMAL
    /// request-role DML table: the boot-time blanket grant covers it and there is NO
    /// REVOKE pass, so the projection writes it under RLS on the consumer scope and
    /// the recipient reads/updates their own rows under RLS on the request path. The
    /// <c>tenant_isolation</c> policy is the SAME fail-closed policy every other
    /// tenant-owned table uses; FORCE is mandatory because the migrating (bypass)
    /// role owns the table.
    /// </summary>
    /// <inheritdoc />
    internal partial class Notifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "notifications",
                schema: "platform",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    recipient_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    source_event_id = table.Column<Guid>(type: "uuid", nullable: false),
                    type = table.Column<string>(type: "text", nullable: false),
                    data = table.Column<string>(type: "jsonb", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    read_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_notifications", x => x.id);
                });

            // The dedup key: at-least-once redelivery of the same event re-projects
            // the same (event, recipient) pair, hits this unique index, and the
            // consumer treats the violation as success. Keyed on the pair (not the
            // event id alone) so a single event MAY fan out to several recipients
            // later without an id collision.
            migrationBuilder.CreateIndex(
                name: "ux_notifications_source_event_recipient",
                schema: "platform",
                table: "notifications",
                columns: new[] { "source_event_id", "recipient_user_id" },
                unique: true);

            // The inbox LIST: keyset (created_at desc, id desc) within the caller's
            // own rows in the active tenant.
            migrationBuilder.CreateIndex(
                name: "ix_notifications_tenant_recipient_created",
                schema: "platform",
                table: "notifications",
                columns: new[] { "tenant_id", "recipient_user_id", "created_at", "id" },
                descending: new[] { false, false, true, true });

            // The PARTIAL index backing the unread-count poll (a badge, polled every
            // few seconds) and the read-all bulk UPDATE. It stays small because
            // unread rows are self-limiting (users clear them), so a count never
            // walks the caller's whole append-mostly history. The standard
            // skewed-nullable-flag idiom.
            migrationBuilder.CreateIndex(
                name: "ix_notifications_unread",
                schema: "platform",
                table: "notifications",
                columns: new[] { "tenant_id", "recipient_user_id" },
                filter: "read_at is null");

            // Row-level security on the tenant-owned inbox (in-app-notifications.md
            // section 2): the SAME fail-closed tenant_isolation policy every other
            // tenant-owned table uses (keyed on tenant_id). FORCE is mandatory - the
            // migrating (bypass) role owns the table and only BYPASSRLS lets it
            // through, so the request role (a non-owner grantee) is bound.
            // nullif(current_setting(...), '') maps a reset-placeholder empty string
            // back to NULL, so a no-tenant read matches zero rows and a no-tenant
            // INSERT fails WITH CHECK - never an error, never a leak. The per-USER
            // narrowing (recipient_user_id = caller) is applied by the query/service,
            // ON TOP of this per-TENANT boundary.
            migrationBuilder.Sql("""
                alter table platform.notifications enable row level security;
                alter table platform.notifications force row level security;
                create policy tenant_isolation on platform.notifications
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on platform.notifications;");

            migrationBuilder.DropTable(
                name: "notifications",
                schema: "platform");
        }
    }
}
