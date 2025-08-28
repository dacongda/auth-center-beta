using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258271 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "scene_id",
                table: "provider",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "scene_id",
                table: "provider");
        }
    }
}
