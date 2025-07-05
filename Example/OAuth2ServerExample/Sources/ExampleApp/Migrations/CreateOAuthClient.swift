import Fluent

struct CreateOAuthClient: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema("oauth_clients")
            .id()
            .field("client_id", .string, .required)
            .field("client_secret", .string, .required)
            .field("redirect_uris", .array(of: .string), .required)
            .field("valid_scopes", .array(of: .string), .required)
            .field("confidential_client", .bool, .required)
            .field("first_party", .bool, .required)
            .field("allowed_grant_type", .string, .required)
            .field("created_at", .datetime)
            .unique(on: "client_id")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("oauth_clients").delete()
    }
} 