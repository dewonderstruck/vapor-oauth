import Foundation

public struct EmptyDeviceCodeManager: DeviceCodeManager {
    public func updateLastPolled(_ deviceCode: String) async throws {
        return
    }

    public func increaseInterval(_ deviceCode: String, by seconds: Int) async throws {
        return
    }

    public func authorizeDeviceCode(_ deviceCode: OAuthDeviceCode, userID: String) async throws {
        return
    }

    public func removeDeviceCode(_ deviceCode: OAuthDeviceCode) async throws {
        return
    }

    public init() {}

    public func generateDeviceCode(
        clientID: String,
        scopes: [String]?,
        verificationURI: String,
        verificationURIComplete: String?
    ) async throws -> OAuthDeviceCode? {
        return nil
    }

    public func getDeviceCode(_ code: String) async throws -> OAuthDeviceCode? {
        return nil
    }

    public func getUserCode(_ code: String) async throws -> OAuthDeviceCode? {
        return nil
    }
}
