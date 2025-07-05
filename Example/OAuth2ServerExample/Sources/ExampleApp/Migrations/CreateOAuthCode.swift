import Fluent

struct CreateOAuthCode: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema("oauth_codes")
            .id()
            .field("code_id", .string, .required)
            .field("client_id", .string, .required)
            .field("redirect_uri", .string, .required)
            .field("user_id", .string, .required)
            .field("scopes", .array(of: .string))
            .field("expiry_date", .datetime, .required)
            .field("code_challenge", .string)
            .field("code_challenge_method", .string)
            .field("used", .bool, .required)
            .field("created_at", .datetime)
            .unique(on: "code_id")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("oauth_codes").delete()
    }
}