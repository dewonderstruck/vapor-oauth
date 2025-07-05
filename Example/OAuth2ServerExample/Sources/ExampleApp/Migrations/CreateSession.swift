import Fluent

struct CreateSession: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema("sessions")
            .id()
            .field("token", .string, .required)
            .field("user_id", .uuid, .required)
            .field("expires_at", .datetime, .required)
            .field("ip_address", .string)
            .field("user_agent", .string)
            .field("created_at", .datetime)
            .unique(on: "token")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("sessions").delete()
    }
} 