import Foundation

public protocol DeviceCodeManager: Sendable {
    func generateDeviceCode(
        clientID: String,
        scopes: [String]?,
        verificationURI: String,
        verificationURIComplete: String?
    ) async throws -> OAuthDeviceCode?

    func getDeviceCode(_ deviceCode: String) async throws -> OAuthDeviceCode?
    func getUserCode(_ code: String) async throws -> OAuthDeviceCode?
    func authorizeDeviceCode(_ deviceCode: OAuthDeviceCode, userID: String) async throws
    func removeDeviceCode(_ deviceCode: OAuthDeviceCode) async throws
    func updateLastPolled(_ deviceCode: String) async throws
    func increaseInterval(_ deviceCode: String, by seconds: Int) async throws
}
