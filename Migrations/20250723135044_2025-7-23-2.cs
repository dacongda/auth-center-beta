using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20257232 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_parent_group",
                table: "application");

            migrationBuilder.DropForeignKey(
                name: "fk_default_application",
                table: "group");

            migrationBuilder.AddForeignKey(
                name: "fk_application_group_group_id",
                table: "application",
                column: "group_id",
                principalTable: "group",
                principalColumn: "id");

            migrationBuilder.AddForeignKey(
                name: "fk_group_application_default_application_id",
                table: "group",
                column: "default_application_id",
                principalTable: "application",
                principalColumn: "id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_application_group_group_id",
                table: "application");

            migrationBuilder.DropForeignKey(
                name: "fk_group_application_default_application_id",
                table: "group");

            migrationBuilder.AddForeignKey(
                name: "fk_parent_group",
                table: "application",
                column: "group_id",
                principalTable: "group",
                principalColumn: "id");

            migrationBuilder.AddForeignKey(
                name: "fk_default_application",
                table: "group",
                column: "default_application_id",
                principalTable: "application",
                principalColumn: "id");
        }
    }
}
