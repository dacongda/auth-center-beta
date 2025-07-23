using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _2025551 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "top_id",
                table: "group",
                type: "integer",
                nullable: true);

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$rhz2ALVYCWvFj8A79FFwX.5J6oMXJaid0l4X2FKW5bJ64kT58t7D6");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "top_id",
                table: "group");

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$8GRleU0bQK5ipyTUFJ8lSeG8dZy7nhNETiTOrKvQ6ji/pzWBfzROu");
        }
    }
}
