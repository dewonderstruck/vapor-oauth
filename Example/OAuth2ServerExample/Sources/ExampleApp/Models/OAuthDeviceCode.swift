import Fluent
import Vapor
import VaporOAuth

final class OAuthDeviceCode: Model, @unchecked Sendable {
    static let schema = "oauth_device_codes"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "device_code")
    var deviceCode: String
    
    @Field(key: "user_code")
    var userCode: String
    
    @Field(key: "client_id")
    var clientID: String
    
    @Field(key: "verification_uri")
    var verificationURI: String
    
    @Field(key: "verification_uri_complete")
    var verificationURIComplete: String?
    
    @Field(key: "expiry_date")
    var expiryDate: Date
    
    @Field(key: "interval")
    var interval: Int
    
    @Field(key: "scopes")
    var scopes: [String]?
    
    @Field(key: "status")
    var status: String // "pending", "authorized", "unauthorized", "declined"
    
    @Field(key: "user_id")
    var userID: String?
    
    @Field(key: "last_polled")
    var lastPolled: Date?
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        deviceCode: String,
        userCode: String,
        clientID: String,
        verificationURI: String,
        verificationURIComplete: String?,
        expiryDate: Date,
        interval: Int,
        scopes: [String]?,
        status: String = "pending",
        userID: String? = nil,
        lastPolled: Date? = nil
    ) {
        self.id = id
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
    
    func toOAuthDeviceCode() -> VaporOAuth.OAuthDeviceCode {
        let deviceCodeStatus: DeviceCodeStatus
        switch status {
        case "pending":
            deviceCodeStatus = .pending
        case "authorized":
            deviceCodeStatus = .authorized
        case "unauthorized":
            deviceCodeStatus = .unauthorized
        case "declined":
            deviceCodeStatus = .declined
        default:
            deviceCodeStatus = .pending
        }
        
        return VaporOAuth.OAuthDeviceCode(
            deviceCode: deviceCode,
            userCode: userCode,
            clientID: clientID,
            verificationURI: verificationURI,
            verificationURIComplete: verificationURIComplete,
            expiryDate: expiryDate,
            interval: interval,
            scopes: scopes,
            status: deviceCodeStatus,
            userID: userID,
            lastPolled: lastPolled
        )
    }
} 