import Vapor
import Fluent
import VaporOAuth

final class FluentDeviceCodeManager: DeviceCodeManager, @unchecked Sendable {
    private let db: any Database
    
    init(db: any Database) {
        self.db = db
    }
    
    func generateDeviceCode(
        clientID: String,
        scopes: [String]?,
        verificationURI: String,
        verificationURIComplete: String?
    ) async throws -> VaporOAuth.OAuthDeviceCode? {
        let deviceCode = UUID().uuidString
        let userCode = generateUserCode()
        let expiryDate = Date().addingTimeInterval(1800) // 30 minutes
        let interval = 5 // 5 seconds
        
        let code = OAuthDeviceCode(
            deviceCode: deviceCode,
            userCode: userCode,
            clientID: clientID,
            verificationURI: verificationURI,
            verificationURIComplete: verificationURIComplete,
            expiryDate: expiryDate,
            interval: interval,
            scopes: scopes,
            status: "pending"
        )
        
        try await code.save(on: db)
        return code.toOAuthDeviceCode()
    }
    
    func getDeviceCode(_ deviceCode: String) async throws -> VaporOAuth.OAuthDeviceCode? {
        guard let fluentCode = try await OAuthDeviceCode.query(on: db)
            .filter(\.$deviceCode == deviceCode)
            .first() else {
            return nil
        }
        
        return fluentCode.toOAuthDeviceCode()
    }
    
    func getUserCode(_ userCode: String) async throws -> VaporOAuth.OAuthDeviceCode? {
        guard let fluentCode = try await OAuthDeviceCode.query(on: db)
            .filter(\.$userCode == userCode)
            .first() else {
            return nil
        }
        
        return fluentCode.toOAuthDeviceCode()
    }
    
    func authorizeDeviceCode(_ deviceCode: VaporOAuth.OAuthDeviceCode, userID: String) async throws {
        guard let fluentCode = try await OAuthDeviceCode.query(on: db)
            .filter(\.$deviceCode == deviceCode.deviceCode)
            .first() else {
            throw Abort(.internalServerError)
        }
        
        fluentCode.status = "authorized"
        fluentCode.userID = userID
        try await fluentCode.save(on: db)
    }
    
    func removeDeviceCode(_ deviceCode: VaporOAuth.OAuthDeviceCode) async throws {
        try await OAuthDeviceCode.query(on: db)
            .filter(\.$deviceCode == deviceCode.deviceCode)
            .delete()
    }
    
    func updateLastPolled(_ deviceCode: String) async throws {
        guard let fluentCode = try await OAuthDeviceCode.query(on: db)
            .filter(\.$deviceCode == deviceCode)
            .first() else {
            throw Abort(.internalServerError)
        }
        
        fluentCode.lastPolled = Date()
        try await fluentCode.save(on: db)
    }
    
    func increaseInterval(_ deviceCode: String, by seconds: Int) async throws {
        guard let fluentCode = try await OAuthDeviceCode.query(on: db)
            .filter(\.$deviceCode == deviceCode)
            .first() else {
            throw Abort(.internalServerError)
        }
        
        fluentCode.interval += seconds
        try await fluentCode.save(on: db)
    }
    
    private func generateUserCode() -> String {
        let letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        let code1 = String((0..<4).map { _ in letters.randomElement()! })
        let code2 = String((0..<4).map { _ in letters.randomElement()! })
        return "\(code1)-\(code2)"
    }
} 