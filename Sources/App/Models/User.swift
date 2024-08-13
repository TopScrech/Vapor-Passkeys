import Vapor
import Fluent
import WebAuthn

final class User: Model, Content {
    static var schema = "users"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "username")
    var username: String
    
    @Field(key: "password_hash")
    var passwordHash: String?
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    @Children(for: \.$user)
    var children: [WebAuthnCredential]
    
    init() {}
    
    init(
        id: UUID? = nil,
        username: String,
        passwordHash: String? = nil
    ) {
        self.id = id
        self.username = username
        self.passwordHash = passwordHash
    }
}

extension User {
    var webAuthnUser: PublicKeyCredentialUserEntity {
        PublicKeyCredentialUserEntity(id: [UInt8](id!.uuidString.utf8), name: username, displayName: username)
    }
}

extension User: ModelSessionAuthenticatable {}
