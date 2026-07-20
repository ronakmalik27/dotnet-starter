using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Sample.Migrations
{
    /// <inheritdoc />
    internal partial class NoteListKeysetIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Replace the plain owner index with the keyset composite matching
            // the owner-scoped list: (owner_user_id, created_at desc, id desc).
            // The old index is redundant (owner_user_id is the composite's
            // leading column), so it is dropped.
            migrationBuilder.DropIndex(
                name: "ix_notes_owner_user_id",
                schema: "sample",
                table: "notes");

            migrationBuilder.CreateIndex(
                name: "ix_notes_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes",
                columns: new[] { "owner_user_id", "created_at", "id" },
                descending: new[] { false, true, true });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Reversible: drop the composite and restore the plain owner index
            // (index swaps drop cleanly, unlike the forward-only tables).
            migrationBuilder.DropIndex(
                name: "ix_notes_owner_user_id_created_at_id",
                schema: "sample",
                table: "notes");

            migrationBuilder.CreateIndex(
                name: "ix_notes_owner_user_id",
                schema: "sample",
                table: "notes",
                column: "owner_user_id");
        }
    }
}
