using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Sample.Migrations
{
    /// <inheritdoc />
    internal partial class NoteOwner : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "owner_user_id",
                schema: "sample",
                table: "notes",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateIndex(
                name: "ix_notes_owner_user_id",
                schema: "sample",
                table: "notes",
                column: "owner_user_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Reversible: a column and index add drops cleanly (unlike the
            // partitioned/DataProtection tables, which are forward-only).
            migrationBuilder.DropIndex(
                name: "ix_notes_owner_user_id",
                schema: "sample",
                table: "notes");

            migrationBuilder.DropColumn(
                name: "owner_user_id",
                schema: "sample",
                table: "notes");
        }
    }
}
