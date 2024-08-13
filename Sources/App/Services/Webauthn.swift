//
//  File.swift
//  Bisquit-ID
//
//  Created by Sergei Saliukov on 13/8/24.
//

import Vapor
import WebAuthn

extension Application {
    struct WebAuthnKey: StorageKey {
        typealias Value = WebAuthnManager
    }
    
    var webAuthn: WebAuthnManager {
        get {
            guard let webAuthn = storage[WebAuthnKey.self] else {
                fatalError("WebAuthn configuration failed")
            }
            
            return webAuthn
        } set {
            storage[WebAuthnKey.self] = newValue
        }
    }
}

extension Request {
    var webAuthn: WebAuthnManager {
        application.webAuthn
    }
}

//    let webAuthnManager = WebAuthnManager(
//        config: WebAuthnManager.Config(
//            relyingPartyID: "49.13.93.214",
//            relyingPartyName: "Authify",
//            relyingPartyOrigin: "https://49.13.93.214"
//        )
//    )

