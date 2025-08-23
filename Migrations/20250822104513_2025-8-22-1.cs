using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258221 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "third_part_name",
                table: "user_thirdpart_infos",
                type: "text",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "third_part_name",
                table: "user_thirdpart_infos");
        }
    }
}
