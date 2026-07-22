using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Sample.Migrations
{
    /// <inheritdoc />
    internal partial class NoteWorkspace : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "workspace_id",
                schema: "sample",
                table: "notes",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_notes_tenant_id_workspace_id_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes",
                columns: new[] { "tenant_id", "workspace_id", "owner_user_id", "created_at", "id" },
                descending: new[] { false, false, false, true, true });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_notes_tenant_id_workspace_id_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes");

            migrationBuilder.DropColumn(
                name: "workspace_id",
                schema: "sample",
                table: "notes");
        }
    }
}
