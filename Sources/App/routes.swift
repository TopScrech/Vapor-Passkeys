import Fluent
import Vapor
import WebAuthn

func routes(_ app: Application) throws {
    app.get(".well-known", "apple-app-site-association") { req -> Response in
        let appId = "8FQUA2F388.dev.topscrech.Signius"
        
        let responseString =
        """
{
    "webcredentials": {
        "apps": [
            "\(appId)"
        ]
    },
}
"""
        
        let response = try await responseString.encodeResponse(for: req)
        response.headers.contentType = HTTPMediaType(type: "application/json", subType: "json")
        
        return response
    }
    
    let authSessionRoutes = app.grouped(User.sessionAuthenticator())
    
    authSessionRoutes.get("signup") { req -> Response in
        let username = try req.query.get(String.self, at: "username")
        
        let userCount = try await User.query(on: req.db).count()
        print("Total Users Count: \(userCount)")
        
        if let existingUser = try await User.query(on: req.db)
            .filter(\.$username == username)
            .first() {
            print("Username \(existingUser.username) is already taken.")
            throw Abort(.conflict, reason: "Username \(username) taken")
        } else {
            print("Username \(username) is available")
        }
        
        let user = User(username: username)
        
        try await user.create(on: req.db)
        print("User \(username) created successfully.")
        
        req.auth.login(user)
        
        return req.redirect(to: "makeCredential")
    }
    
    authSessionRoutes.get("makeCredential") { req -> PublicKeyCredentialCreationOptions in
        // Ensure the user is authenticated
        let user = try req.auth.require(User.self)
        print("Authenticated user: \(user.username) (ID: \(user.id?.uuidString ?? "unknown"))")
        
        // Begin the WebAuthn registration process
        let options: PublicKeyCredentialCreationOptions
        
        options = req.webAuthn.beginRegistration(user: user.webAuthnUser)
        print("WebAuthn registration started for user: \(user.username)")
        
        // Store the challenge in the session data
        let challenge = Data(options.challenge).base64EncodedString()
        req.session.data["registrationChallenge"] = challenge
        print("Stored registration challenge in session for user: \(user.username)")
        
        // Log the challenge details (avoid sensitive details for security reasons)
        print("Challenge (base64-encoded): \(challenge)")
        
        // Return the options for the credential creation
        return options
    }
    
//    authSessionRoutes.get("makeCredential") { req -> PublicKeyCredentialCreationOptions in
//        let user = try req.auth.require(User.self)
//        
//        let options = req.webAuthn.beginRegistration(user: user.webAuthnUser)
//        
//        req.session.data["registrationChallenge"] = Data(options.challenge).base64EncodedString()
//        
//        return options
//    }
    
    authSessionRoutes.post("makeCredential") { req -> HTTPStatus in
        let user = try req.auth.require(User.self)
        
        guard let challengeEncoded = req.session.data["registrationChallenge"], let challenge = Data(base64Encoded: challengeEncoded) else {
            throw Abort(.badRequest, reason: "Error encoding challenge")
        }
        
        req.session.data["registrationChallenge"] = nil
        
        let credential = try await req.webAuthn.finishRegistration(challenge: [UInt8](challenge), credentialCreationData: req.content.decode(RegistrationCredential.self)) { credentialID in
            let existingCredential = try await WebAuthnCredential.query(on: req.db)
                .filter(\.$id == credentialID)
                .first()
            return existingCredential == nil
        }
        
        try await WebAuthnCredential(from: credential, userID: user.requireID())
            .save(on: req.db)
        
        return .ok
    }
    
    authSessionRoutes.get("authenticate") { req -> PublicKeyCredentialRequestOptions in
        let options = try req.webAuthn.beginAuthentication()
        
        req.session.data["authChallenge"] = Data(options.challenge).base64EncodedString()
        
        return options
    }
    
    authSessionRoutes.post("authenticate") { req -> Response in
        guard let challengeEncoded = req.session.data["authChallenge"], let challenge = Data(base64Encoded: challengeEncoded) else {
            throw Abort(.badRequest, reason: "Error retrieving and encoding challenge from server")
        }
        
        req.session.data["authChallenge"] = nil
        
        let authenticationCredential = try req.content.decode(AuthenticationCredential.self)
        
        guard let credential = try await WebAuthnCredential.query(on: req.db)
            .filter(\.$id == authenticationCredential.id.urlDecoded.asString())
            .with(\.$user)
            .first()
        else {
            throw Abort(.unauthorized, reason: "Error finding WebAuthnCredential from database")
        }
        
        let verifiedAuthentication = try req.webAuthn.finishAuthentication(credential: authenticationCredential, expectedChallenge: [UInt8](challenge), credentialPublicKey: [UInt8](URLEncodedBase64(credential.publicKey).urlDecoded.decoded!), credentialCurrentSignCount: UInt32(credential.currentSignCount))
        
        credential.currentSignCount = Int32(verifiedAuthentication.newSignCount)
        try await credential.save(on: req.db)
        
        return Response(status: .ok)
    }
    
    authSessionRoutes.get("sighout") { req -> Response in
        req.auth.logout(User.self)
        return Response(status: .ok)
    }
    
    authSessionRoutes.delete("deleteCredential") { req -> Response in
        let user = try req.auth.require(User.self)
        
        try await user.delete(on: req.db)
        
        return Response(status: .noContent)
    }
}

extension PublicKeyCredentialCreationOptions: AsyncResponseEncodable {
    public func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        
        return try Response(status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}

extension PublicKeyCredentialRequestOptions: AsyncResponseEncodable {
    public func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        
        return try Response(status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}
