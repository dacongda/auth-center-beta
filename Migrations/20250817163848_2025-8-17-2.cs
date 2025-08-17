using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258172 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_group_default_application_id",
                table: "group");

            migrationBuilder.CreateIndex(
                name: "ix_group_default_application_id",
                table: "group",
                column: "default_application_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_group_default_application_id",
                table: "group");

            migrationBuilder.CreateIndex(
                name: "ix_group_default_application_id",
                table: "group",
                column: "default_application_id",
                unique: true);
        }
    }
}
