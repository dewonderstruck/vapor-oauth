import Foundation

public final class OAuthDeviceCode: @unchecked Sendable {
    public let deviceCode: String
    public let userCode: String
    public let clientID: String
    public let verificationURI: String
    public let verificationURIComplete: String?
    public let expiryDate: Date
    public let interval: Int
    public let scopes: [String]?
    public var status: DeviceCodeStatus
    public var userID: String?
    public let lastPolled: Date?
    
    public var shouldIncreasePollInterval: Bool {
        guard let lastPolled = lastPolled else { return false }
        return Date().timeIntervalSince(lastPolled) < Double(interval)
    }
    
    public init(
        deviceCode: String,
        userCode: String,
        clientID: String,
        verificationURI: String,
        verificationURIComplete: String?,
        expiryDate: Date,
        interval: Int,
        scopes: [String]?,
        status: DeviceCodeStatus = .pending,
        userID: String? = nil,
        lastPolled: Date? = nil
    ) {
        self.deviceCode = deviceCode
        self.userCode = userCode
        self.clientID = clientID
        self.verificationURI = verificationURI
        self.verificationURIComplete = verificationURIComplete
        self.expiryDate = expiryDate
        self.interval = interval
        self.scopes = scopes
        self.status = status
        self.userID = userID
        self.lastPolled = lastPolled
    }
}

public enum DeviceCodeStatus {
    case pending
    case authorized
    case unauthorized
    case declined
}
