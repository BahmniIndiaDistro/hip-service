using Microsoft.EntityFrameworkCore.Migrations;

namespace In.ProjectEKA.HipService.Migrations
{
    public partial class AddHipIdToAuthConfirm : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm");

            migrationBuilder.AddColumn<string>(
                name: "HipId",
                table: "AuthConfirm",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm",
                columns: new[] { "HealthId", "HipId" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm");

            migrationBuilder.DropColumn(
                name: "HipId",
                table: "AuthConfirm");

            migrationBuilder.AddPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm",
                column: "HealthId");
        }
    }
}
