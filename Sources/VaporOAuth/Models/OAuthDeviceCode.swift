import Foundation

/// A device authorization grant issued during the OAuth 2.0 device authorization flow
///
/// Device authorization grants are used to obtain access tokens for devices with limited input capabilities
/// as defined in [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628). The flow involves:
///
/// 1. The client requests device and user codes from the authorization server
/// 2. The authorization server issues a device code and user code
/// 3. The user enters the user code at a verification URI to authorize the device
/// 4. The client polls the token endpoint with the device code to obtain an access token
///
/// The device code response includes:
/// - A device code used to poll for authorization status
/// - A user code to be entered by the user
/// - A verification URI where the user enters the code
/// - An optional complete verification URI including the user code
/// - The lifetime of the codes
/// - The minimum interval between polling requests
public final class OAuthDeviceCode: @unchecked Sendable {
    /// The device verification code
    public let deviceCode: String

    /// The user verification code that should be displayed to the user
    public let userCode: String

    /// The client identifier the device code was issued to
    public let clientID: String

    /// The verification URI where the user should enter the user code
    public let verificationURI: String

    /// Optional verification URI that includes the user code
    public let verificationURIComplete: String?

    /// When this device code expires
    public let expiryDate: Date

    /// The minimum number of seconds between polling requests
    public let interval: Int

    /// The scope of access requested by the client
    public let scopes: [String]?

    /// The current status of this device authorization grant
    public var status: DeviceCodeStatus

    /// Identifier of the resource owner who authorized the device, if any
    public var userID: String?

    /// When the device code was last used to poll for an access token
    public let lastPolled: Date?

    /// Whether the client should slow down polling based on the minimum interval
    public var shouldIncreasePollInterval: Bool {
        guard let lastPolled = lastPolled else { return false }
        return Date().timeIntervalSince(lastPolled) < Double(interval)
    }

    /// Initialize a new device authorization grant
    /// - Parameters:
    ///   - deviceCode: The device verification code
    ///   - userCode: The user verification code
    ///   - clientID: The client identifier the code was issued to
    ///   - verificationURI: The verification URI for user code entry
    ///   - verificationURIComplete: Optional verification URI including the user code
    ///   - expiryDate: When this device code expires
    ///   - interval: The minimum polling interval in seconds
    ///   - scopes: The scope of access requested
    ///   - status: The current authorization status
    ///   - userID: Identifier of the authorizing user
    ///   - lastPolled: When the code was last used to poll for a token
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

/// The status of a device authorization grant
///
/// As defined in [RFC 8628 Section 3.3](https://datatracker.ietf.org/doc/html/rfc8628#section-3.3),
/// device code status can be:
/// - Pending: Waiting for user authorization
/// - Authorized: User has approved the device
/// - Unauthorized: User has not yet approved or denied
/// - Declined: User has denied authorization
public enum DeviceCodeStatus {
    case pending
    case authorized
    case unauthorized
    case declined
}
