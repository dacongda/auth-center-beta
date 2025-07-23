using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _2025510 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "parent_chain",
                table: "group",
                type: "text",
                nullable: true);

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$6zAIC1EWsrxlit65iwLlVez9zDjnWwE8A2RQt0Ob/OTLa/PRyP1Di");

            migrationBuilder.CreateIndex(
                name: "ix_group_name",
                table: "group",
                column: "name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_group_name",
                table: "group");

            migrationBuilder.DropColumn(
                name: "parent_chain",
                table: "group");

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$rhz2ALVYCWvFj8A79FFwX.5J6oMXJaid0l4X2FKW5bJ64kT58t7D6");
        }
    }
}
