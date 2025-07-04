import Foundation

@testable import VaporOAuth

final class FakeDeviceCodeManager: DeviceCodeManager, @unchecked Sendable {
    internal var deviceCodes: [String: OAuthDeviceCode] = [:]
    internal var userCodes: [String: OAuthDeviceCode] = [:]

    var shouldFailGeneration = false
    var shouldFailRetrieval = false
    var shouldFailAuthorization = false
    var shouldFailRemoval = false

    // Track method calls for verification in tests
    private(set) var generateDeviceCodeCalls:
        [(clientID: String, scopes: [String]?, verificationURI: String, verificationURIComplete: String?)] = []
    private(set) var getDeviceCodeCalls: [String] = []
    private(set) var getUserCodeCalls: [String] = []
    private(set) var authorizeDeviceCodeCalls: [(deviceCode: OAuthDeviceCode, userID: String)] = []
    private(set) var removeDeviceCodeCalls: [OAuthDeviceCode] = []

    // Add new properties to track polling-related calls
    private(set) var updateLastPolledCalls: [String] = []
    private(set) var increaseIntervalCalls: [(deviceCode: String, seconds: Int)] = []

    func generateDeviceCode(
        clientID: String,
        scopes: [String]?,
        verificationURI: String,
        verificationURIComplete: String?
    ) async throws -> OAuthDeviceCode? {
        generateDeviceCodeCalls.append((clientID, scopes, verificationURI, verificationURIComplete))

        if shouldFailGeneration {
            return nil
        }

        let deviceCode = OAuthDeviceCode(
            deviceCode: UUID().uuidString,
            userCode: generateUserCode(),
            clientID: clientID,
            verificationURI: verificationURI,
            verificationURIComplete: verificationURIComplete,
            expiryDate: Date().addingTimeInterval(600),  // 10 minutes
            interval: 5,
            scopes: scopes
        )

        deviceCodes[deviceCode.deviceCode] = deviceCode
        userCodes[deviceCode.userCode] = deviceCode

        return deviceCode
    }

    func getDeviceCode(_ code: String) async throws -> OAuthDeviceCode? {
        getDeviceCodeCalls.append(code)

        if shouldFailRetrieval {
            return nil
        }

        // Simulate replay protection: if code is not present, return nil
        return deviceCodes[code]
    }

    func getUserCode(_ code: String) async throws -> OAuthDeviceCode? {
        getUserCodeCalls.append(code)

        if shouldFailRetrieval {
            return nil
        }

        return userCodes[code]
    }

    func authorizeDeviceCode(_ deviceCode: OAuthDeviceCode, userID: String) async throws {
        authorizeDeviceCodeCalls.append((deviceCode, userID))

        if shouldFailAuthorization {
            throw DeviceCodeError.authorizationFailed
        }

        deviceCode.status = .authorized
        deviceCode.userID = userID
    }

    func removeDeviceCode(_ deviceCode: OAuthDeviceCode) async throws {
        removeDeviceCodeCalls.append(deviceCode)

        if shouldFailRemoval {
            throw DeviceCodeError.removalFailed
        }

        deviceCodes.removeValue(forKey: deviceCode.deviceCode)
        userCodes.removeValue(forKey: deviceCode.userCode)
    }

    func updateLastPolled(_ deviceCode: String) async throws {
        updateLastPolledCalls.append(deviceCode)

        guard let code = deviceCodes[deviceCode] else {
            return
        }

        let updatedCode = OAuthDeviceCode(
            deviceCode: code.deviceCode,
            userCode: code.userCode,
            clientID: code.clientID,
            verificationURI: code.verificationURI,
            verificationURIComplete: code.verificationURIComplete,
            expiryDate: code.expiryDate,
            interval: code.interval,
            scopes: code.scopes,
            status: code.status,
            userID: code.userID,
            lastPolled: Date()  // Update the last polled time
        )

        deviceCodes[deviceCode] = updatedCode
        userCodes[updatedCode.userCode] = updatedCode
    }

    func increaseInterval(_ deviceCode: String, by seconds: Int) async throws {
        increaseIntervalCalls.append((deviceCode, seconds))

        guard let code = deviceCodes[deviceCode] else {
            return
        }

        let updatedCode = OAuthDeviceCode(
            deviceCode: code.deviceCode,
            userCode: code.userCode,
            clientID: code.clientID,
            verificationURI: code.verificationURI,
            verificationURIComplete: code.verificationURIComplete,
            expiryDate: code.expiryDate,
            interval: code.interval + seconds,  // Increase the interval
            scopes: code.scopes,
            status: code.status,
            userID: code.userID,
            lastPolled: code.lastPolled
        )

        deviceCodes[deviceCode] = updatedCode
        userCodes[updatedCode.userCode] = updatedCode
    }

    // MARK: - Helper Methods

    private func generateUserCode() -> String {
        // Generate a user-friendly code (e.g., "ABCD-1234")
        let letters = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")  // Excluding I and O to avoid confusion
        let numbers = Array("0123456789")

        let letterPart = String((0..<4).map { _ in letters.randomElement()! })
        let numberPart = String((0..<4).map { _ in numbers.randomElement()! })

        return "\(letterPart)-\(numberPart)"
    }

    // MARK: - Test Helper Methods

    func reset() {
        deviceCodes.removeAll()
        userCodes.removeAll()
        generateDeviceCodeCalls.removeAll()
        getDeviceCodeCalls.removeAll()
        getUserCodeCalls.removeAll()
        authorizeDeviceCodeCalls.removeAll()
        removeDeviceCodeCalls.removeAll()
        updateLastPolledCalls.removeAll()
        increaseIntervalCalls.removeAll()

        shouldFailGeneration = false
        shouldFailRetrieval = false
        shouldFailAuthorization = false
        shouldFailRemoval = false
    }

    func addTestDeviceCode(
        deviceCode: String = "test_device_code",
        userCode: String = "TEST-1234",
        clientID: String,
        scopes: [String]? = nil,
        status: DeviceCodeStatus = .pending,
        userID: String? = nil,
        expiryDate: Date? = nil,
        interval: Int = 5,
        lastPolled: Date? = nil
    ) -> OAuthDeviceCode {
        let code = OAuthDeviceCode(
            deviceCode: deviceCode,
            userCode: userCode,
            clientID: clientID,
            verificationURI: "/oauth/device/verify",
            verificationURIComplete: nil,
            expiryDate: expiryDate ?? Date().addingTimeInterval(600),
            interval: interval,
            scopes: scopes,
            status: status,
            userID: userID,
            lastPolled: lastPolled
        )

        deviceCodes[code.deviceCode] = code
        userCodes[code.userCode] = code

        return code
    }
}

// MARK: - Error Types
enum DeviceCodeError: Error {
    case authorizationFailed
    case removalFailed
}
