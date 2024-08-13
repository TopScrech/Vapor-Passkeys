import Fluent

struct CreateUsers: AsyncMigration {
    func prepare(on database: FluentKit.Database) async throws {
        try await database.schema("users")
            .id()
            .field("username", .string, .required)
            .field("password_hash", .string)
            .field("created_at", .datetime, .required)
            .unique(on: "username")
            .create()
    }
    
    func revert(on database: Database) async throws {
        try await database.schema("users").delete()
    }
}
