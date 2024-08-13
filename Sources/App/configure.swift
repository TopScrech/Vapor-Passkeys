import NIOSSL
import Fluent
import FluentPostgresDriver
import Vapor
import WebAuthn

// configures your application
public func configure(_ app: Application) async throws {
    // uncomment to serve files from /Public folder
    //     app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))
    
    app.middleware.use(app.sessions.middleware)
    
    app.databases.use(DatabaseConfigurationFactory.postgres(configuration: .init(
        hostname: "49.13.93.214",
        port: 5432,
        username: "topscrech",
        password: "481664",
        database: "Authify",
        tls: .disable)
    ), as: .psql)
    
    app.sessions.use(.fluent)
    
    app.migrations.add(CreateUsers())
    app.migrations.add(CreateWebauthnCredential())
    
    try await app.autoMigrate()
    
    let domain = ""
    app.webAuthn = WebAuthnManager(config: .init(
        relyingPartyID: "\(domain)/",
        relyingPartyName: "Signius",
        relyingPartyOrigin: "http://\(domain)"
    ))
#warning("https")
    
    try routes(app)
}
