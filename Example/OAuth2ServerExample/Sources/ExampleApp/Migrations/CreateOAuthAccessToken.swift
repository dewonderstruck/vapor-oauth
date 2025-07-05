import Fluent

struct CreateOAuthAccessToken: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema("oauth_access_tokens")
            .id()
            .field("token_string", .string, .required)
            .field("client_id", .string, .required)
            .field("user_id", .string)
            .field("scopes", .array(of: .string))
            .field("expiry_time", .datetime, .required)
            .field("created_at", .datetime)
            .unique(on: "token_string")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("oauth_access_tokens").delete()
    }
} 