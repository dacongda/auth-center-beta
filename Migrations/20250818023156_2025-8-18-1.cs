using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258181 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "link_body",
                table: "provider",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "link_body",
                table: "provider");
        }
    }
}
