import Fluent

struct CreateOAuthDeviceCode: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("oauth_device_codes")
            .id()
            .field("device_code", .string, .required)
            .field("user_code", .string, .required)
            .field("client_id", .string, .required)
            .field("verification_uri", .string, .required)
            .field("verification_uri_complete", .string)
            .field("expiry_date", .datetime, .required)
            .field("interval", .int, .required)
            .field("scopes", .array(of: .string))
            .field("status", .string, .required)
            .field("user_id", .string)
            .field("last_polled", .datetime)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .unique(on: "device_code")
            .unique(on: "user_code")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("oauth_device_codes").delete()
    }
} 