using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <inheritdoc />
    internal partial class Outbox : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "platform");

            // domain_events is partitioned monthly by occurred_at and kept
            // forever (doc 07 section 3, INV-8). EF cannot express PARTITION
            // BY, so the parent, its partitions, and its doc 07 section 12
            // indexes are raw SQL; the entity mapping is marked
            // ExcludeFromMigrations. Partitions cover a 2026-2027 window plus
            // a DEFAULT catch-all so no insert can ever fail; extending the
            // monthlies is an ops-calendar item (doc 11 section 10) before
            // 2028.
            migrationBuilder.Sql("""
                create table platform.domain_events (
                  id             uuid        not null,
                  occurred_at    timestamptz not null,
                  module         text        not null,
                  event_type     text        not null,
                  entity_id      uuid        not null,
                  trip_id        uuid        null,
                  actor_user_id  uuid        null,
                  payload        jsonb       not null,
                  primary key (id, occurred_at)
                ) partition by range (occurred_at);

                do $$
                declare m date := date '2026-01-01';
                begin
                  while m < date '2028-01-01' loop
                    execute format(
                      'create table platform.domain_events_%s partition of platform.domain_events for values from (%L) to (%L)',
                      to_char(m, 'YYYY_MM'), m, m + interval '1 month');
                    m := (m + interval '1 month')::date;
                  end loop;
                end $$;

                create table platform.domain_events_default
                  partition of platform.domain_events default;

                -- Doc 07 section 12: replay, per-trip timelines, AI extraction.
                create index ix_domain_events_trip_id_occurred_at
                  on platform.domain_events (trip_id, occurred_at);
                create index ix_domain_events_event_type_occurred_at
                  on platform.domain_events (event_type, occurred_at);
                """);

            migrationBuilder.CreateTable(
                name: "outbox",
                schema: "platform",
                columns: table => new
                {
                    event_id = table.Column<Guid>(type: "uuid", nullable: false),
                    lane = table.Column<string>(type: "text", nullable: false),
                    enqueued_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    next_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    delivered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    poisoned_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_outbox", x => new { x.event_id, x.lane });
                    table.CheckConstraint("ck_outbox_lane", "lane in ('fast','slow')");
                });

            migrationBuilder.CreateIndex(
                name: "ix_outbox_lane_next_attempt_at",
                schema: "platform",
                table: "outbox",
                columns: new[] { "lane", "next_attempt_at" },
                filter: "delivered_at is null and poisoned_at is null");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Forward-only (doc 07 section 14): no down-migrations.
        }
    }
}
