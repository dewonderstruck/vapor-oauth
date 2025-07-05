import Vapor
import Fluent

struct CreateOAuthResourceServer: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("oauth_resource_servers")
            .id()
            .field("username", .string, .required)
            .field("password", .string, .required)
            .field("created_at", .datetime)
            .unique(on: "username")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("oauth_resource_servers").delete()
    }
} 