using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <inheritdoc />
    internal partial class DsarEventSpineIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Index the event-spine tenant columns so a tenant erasure's
            // `delete .. where tenant_id = @t` over them is an index scan, not a
            // sequential scan of an ever-growing table inside the single bypass
            // transaction that also holds locks on 16+ other tables
            // (data-export-and-erasure.md section 4). domain_events is the raw-SQL
            // partitioned parent (ExcludeFromMigrations), so its index is hand-written
            // SQL too and propagates to every partition via the parent. Both tables are
            // empty at migration time in this starter, so a plain CREATE INDEX is fine;
            // on a populated production table use CREATE INDEX CONCURRENTLY out of band.
            migrationBuilder.Sql(
                "create index if not exists ix_domain_events_tenant_id "
                + "on platform.domain_events (tenant_id);");
            migrationBuilder.Sql(
                "create index if not exists ix_outbox_tenant_id "
                + "on platform.outbox (tenant_id);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop index if exists platform.ix_outbox_tenant_id;");
            migrationBuilder.Sql("drop index if exists platform.ix_domain_events_tenant_id;");
        }
    }
}
