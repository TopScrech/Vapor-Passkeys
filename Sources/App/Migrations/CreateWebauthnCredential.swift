import Fluent

struct CreateAuthnCredential: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("webAuthn_Credentials")
            .field("id", .string, .identifier(auto: false))
            .field("public_key", .string, .required)
            .field("current_signCOunt", .uint32, .required)
            .field("user_id", .uuid, .references("users", "id", onDelete: .cascade))
            .unique(on: "id")
            .create()
    }
    
    func revert(on database: Database) async throws {
        try await database.schema("webAuthn_Credentials").delete()
    }
}

