using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <inheritdoc />
    internal partial class TenantScope : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The event spine gains tenant_id: not-null for tenant-owned work,
            // null for a platform event (OutboxWriter stamps it at enqueue).
            migrationBuilder.AddColumn<Guid>(
                name: "tenant_id",
                schema: "platform",
                table: "outbox",
                type: "uuid",
                nullable: true);

            // domain_events is the raw-SQL partitioned table (ExcludeFromMigrations),
            // so the column add is hand-written. ADD COLUMN on the partitioned
            // parent cascades to every partition.
            migrationBuilder.Sql(
                "alter table platform.domain_events add column tenant_id uuid null;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Forward-only: no down-migration (domain_events is forward-only
            // like the rest of the partitioned/DataProtection tables).
        }
    }
}
