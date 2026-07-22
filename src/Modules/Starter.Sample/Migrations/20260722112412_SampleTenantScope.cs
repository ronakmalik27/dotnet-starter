using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Sample.Migrations
{
    /// <inheritdoc />
    internal partial class SampleTenantScope : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The old (owner, sort) index gives way to the tenant-leading one:
            // every query is now tenant-scoped, so tenant_id is the equality
            // prefix.
            migrationBuilder.DropIndex(
                name: "ix_notes_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes");

            // Add tenant_id with a temporary empty-guid default so the add
            // succeeds on any (in the template: empty) existing rows, then drop
            // the default immediately below so a future INSERT that forgets to
            // stamp the tenant fails loudly rather than silently landing an
            // empty tenant that RLS would then reject.
            migrationBuilder.AddColumn<Guid>(
                name: "tenant_id",
                schema: "sample",
                table: "notes",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));
            migrationBuilder.Sql("alter table sample.notes alter column tenant_id drop default;");

            migrationBuilder.CreateTable(
                name: "note_index",
                schema: "sample",
                columns: table => new
                {
                    note_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    title_length = table.Column<int>(type: "integer", nullable: false),
                    visible_note_count = table.Column<int>(type: "integer", nullable: false),
                    indexed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_note_index", x => x.note_id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_notes_tenant_id_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes",
                columns: new[] { "tenant_id", "owner_user_id", "created_at", "id" },
                descending: new[] { false, false, true, true });

            // Row-level security: the authoritative isolation boundary. FORCE is
            // mandatory - the tables are owned by the migrating (bypass) role,
            // and only BYPASSRLS lets it through; a normal owner would otherwise
            // silently skip the policy. The request role is a non-owner grantee,
            // so it is bound by the policy; the bypass role crosses tenants for
            // the control plane and migrations.
            //
            // nullif(..., '') is load-bearing for fail-closed: current_setting
            // with the missing_ok flag returns NULL only if the GUC was NEVER
            // set in the session. Once it has been set once (any prior request
            // on a pooled connection), a reset placeholder GUC reverts to the
            // EMPTY STRING, not NULL - and ''::uuid raises 22P02, turning a
            // no-tenant read into an error rather than zero rows. nullif maps ''
            // back to NULL, so tenant_id = NULL matches nothing (SELECT/UPDATE/
            // DELETE) and WITH CHECK fails (INSERT): fail-closed, never an error
            // and never a leak.
            EnableTenantIsolation(migrationBuilder, "notes");
            EnableTenantIsolation(migrationBuilder, "note_index");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("drop policy if exists tenant_isolation on sample.note_index;");
            migrationBuilder.Sql("drop policy if exists tenant_isolation on sample.notes;");

            migrationBuilder.DropTable(
                name: "note_index",
                schema: "sample");

            migrationBuilder.DropIndex(
                name: "ix_notes_tenant_id_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes");

            migrationBuilder.DropColumn(
                name: "tenant_id",
                schema: "sample",
                table: "notes");

            migrationBuilder.CreateIndex(
                name: "ix_notes_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes",
                columns: new[] { "owner_user_id", "created_at", "id" },
                descending: new[] { false, true, true });
        }

        private static void EnableTenantIsolation(MigrationBuilder migrationBuilder, string table)
        {
            migrationBuilder.Sql($"""
                alter table sample.{table} enable row level security;
                alter table sample.{table} force row level security;
                create policy tenant_isolation on sample.{table}
                  using      (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
                  with check (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);
                """);
        }
    }
}
