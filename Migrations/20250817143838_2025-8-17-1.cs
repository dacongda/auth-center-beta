using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258171 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "disable_signup",
                table: "group",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "disable_signup",
                table: "group");
        }
    }
}
