using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace lrf.auth.api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAllowedScopesAndOidcMetadata : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AllowedScopes",
                table: "oauth_clients",
                type: "varchar(500)",
                maxLength: 500,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowedScopes",
                table: "oauth_clients");
        }
    }
}
