import Fluent
import Vapor
import WebAuthn

func routes(_ app: Application) throws {
    app.get(".well-known", "apple-app-site-association") { req -> Response in
        let appId = "8FQUA2F388.dev.topscrech.Authify"
        
        let responseString =
        """
{
    "webcredentials": {
        "apps": [
            "\(appId)"
        ]
    }
}
"""
        
        let response = try await responseString.encodeResponse(for: req)
        response.headers.contentType = HTTPMediaType(type: "application/json", subType: "json")
        
        return response
    }

    let authSessionRoutes = app.grouped(User.sessionAuthenticator())
    
    authSessionRoutes.get("signup") { req -> Response in
        let username = try req.query.get(String.self, at: "username")
        
        guard try await User.query(on: req.db).first() == nil else {
            throw Abort(.conflict, reason: "Username taken")
        }
        
        let user = User(username: username)
        
        try await user.create(on: req.db)
        req.auth.login(user)
        
        return req.redirect(to: "makeCredential")
    }
    
    authSessionRoutes.get("makeCredential") { req -> PublicKeyCredentialCreationOptions in
        let user = try req.auth.require(User.self)
        
        let options = req.webAuthn.beginRegistration(user: user.webAuthnUser)
        
        req.session.data["registrationChallenge"] = Data(options.challenge).base64EncodedString()
        
        return options
    }
    
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
}

extension PublicKeyCredentialCreationOptions: AsyncResponseEncodable {
    public func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        
        return try Response(status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}
