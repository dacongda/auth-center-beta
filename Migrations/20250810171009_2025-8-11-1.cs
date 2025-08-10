using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258111 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "pk_user_thirdpart_infos",
                table: "user_thirdpart_infos");

            migrationBuilder.AddPrimaryKey(
                name: "pk_user_thirdpart_infos",
                table: "user_thirdpart_infos",
                columns: new[] { "provider_name", "user_id" });

            migrationBuilder.CreateIndex(
                name: "ix_user_thirdpart_infos_third_part_id",
                table: "user_thirdpart_infos",
                column: "third_part_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "pk_user_thirdpart_infos",
                table: "user_thirdpart_infos");

            migrationBuilder.DropIndex(
                name: "ix_user_thirdpart_infos_third_part_id",
                table: "user_thirdpart_infos");

            migrationBuilder.AddPrimaryKey(
                name: "pk_user_thirdpart_infos",
                table: "user_thirdpart_infos",
                columns: new[] { "third_part_id", "provider_name", "user_id" });
        }
    }
}
