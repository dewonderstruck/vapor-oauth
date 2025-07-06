import JWTKit
import Vapor

/// JWT Access Token implementation compliant with RFC 9068
public struct JWTAccessToken: AccessToken, JWTPayload {

    // MARK: - RFC 9068 Required Claims

    /// Issuer claim (iss) - The issuer of the JWT
    public var iss: IssuerClaim

    /// Subject claim (sub) - The subject of the JWT (user ID)
    public var sub: SubjectClaim

    /// Audience claim (aud) - The intended audience (client ID)
    public var aud: AudienceClaim

    /// Expiration time claim (exp) - When the token expires
    public var exp: ExpirationClaim

    /// Issued at claim (iat) - When the token was issued
    public var iat: IssuedAtClaim

    // MARK: - RFC 9068 Optional Claims

    /// JWT ID claim (jti) - Unique identifier for the token
    public var jti: IDClaim

    /// Scope claim (scope) - The scopes granted to the token
    public var scope: String?

    /// Token type claim (token_type) - Should be "Bearer" for access tokens
    public var tokenType: String?

    // MARK: - AccessToken Protocol Conformance

    public var tokenString: String {
        // This will be set when the JWT is serialized
        return ""
    }

    public var clientID: String {
        return aud.value.first ?? ""
    }

    public var userID: String? {
        return sub.value
    }

    public var scopes: [String]? {
        return scope?.components(separatedBy: " ")
    }

    public var expiryTime: Date {
        return exp.value
    }

    // MARK: - Initialization

    public init(
        issuer: String,
        subject: String,
        audience: String,
        expirationTime: Date,
        issuedAt: Date = Date(),
        jwtID: String = UUID().uuidString,
        scope: String? = nil,
        clientID: String? = nil,
        tokenType: String = "Bearer"
    ) {
        self.iss = IssuerClaim(value: issuer)
        self.sub = SubjectClaim(value: subject)
        self.aud = AudienceClaim(value: audience)
        self.exp = ExpirationClaim(value: expirationTime)
        self.iat = IssuedAtClaim(value: issuedAt)
        self.jti = IDClaim(value: jwtID)
        self.scope = scope
        if let clientID = clientID {
            self.aud = AudienceClaim(value: [clientID])
        }
        self.tokenType = tokenType
    }

    // MARK: - JWTPayload Conformance

    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Verify expiration
        try exp.verifyNotExpired()

        // Verify issued at is not in the future
        let now = Date()
        if iat.value > now.addingTimeInterval(5) {  // allow small clock skew
            throw JWTError.claimVerificationFailure(failedClaim: iat, reason: "Issued at time is in the future")
        }
        // Additional custom verification can be added here
    }
}

// MARK: - Extensions for JWT Claims

extension JWTAccessToken {
    /// Create a JWTAccessToken from an existing AccessToken
    public init(from accessToken: any AccessToken, issuer: String) {
        self.init(
            issuer: issuer,
            subject: accessToken.userID ?? "",
            audience: accessToken.clientID,
            expirationTime: accessToken.expiryTime,
            scope: accessToken.scopes?.joined(separator: " "),
            clientID: accessToken.clientID
        )
    }
}
