import JWTKit
import Vapor

/// JWT Refresh Token implementation
public struct JWTRefreshToken: RefreshToken, JWTPayload {

    // MARK: - JWT Claims

    /// Issuer claim (iss) - The issuer of the JWT
    public var iss: IssuerClaim

    /// Subject claim (sub) - The subject of the JWT (user ID)
    public var sub: SubjectClaim

    /// Audience claim (aud) - The intended audience (client ID)
    public var aud: AudienceClaim

    /// Expiration time claim (exp) - When the token expires (optional for refresh tokens)
    public var exp: ExpirationClaim?

    /// Issued at claim (iat) - When the token was issued
    public var iat: IssuedAtClaim

    /// JWT ID claim (jti) - Unique identifier for the token
    public var jti: IDClaim

    /// Scope claim (scope) - The scopes granted to the token
    public var scope: String?

    /// Token type claim (token_type) - Should be "Refresh" for refresh tokens
    public var tokenType: String?

    // MARK: - RefreshToken Protocol Conformance

    public var tokenString: String {
        get {
            // This will be set when the JWT is serialized
            return ""
        }
        set {
            // JWT tokens are immutable, so this is a no-op
        }
    }

    public var clientID: String {
        get {
            return aud.value.first ?? ""
        }
        set {
            self.aud = AudienceClaim(value: [newValue])
        }
    }

    public var userID: String? {
        get {
            return sub.value
        }
        set {
            if let userID = newValue {
                self.sub = SubjectClaim(value: userID)
            }
        }
    }

    public var scopes: [String]? {
        get {
            return scope?.components(separatedBy: " ")
        }
        set {
            self.scope = newValue?.joined(separator: " ")
        }
    }

    // MARK: - Initialization

    public init(
        issuer: String,
        subject: String,
        audience: String,
        issuedAt: Date = Date(),
        expirationTime: Date? = nil,
        jwtID: String = UUID().uuidString,
        scope: String? = nil,
        clientID: String? = nil,
        tokenType: String = "Refresh"
    ) {
        self.iss = IssuerClaim(value: issuer)
        self.sub = SubjectClaim(value: subject)
        self.aud = AudienceClaim(value: audience)
        self.iat = IssuedAtClaim(value: issuedAt)
        self.jti = IDClaim(value: jwtID)
        self.scope = scope
        if let clientID = clientID {
            self.aud = AudienceClaim(value: [clientID])
        }
        self.tokenType = tokenType

        if let expirationTime = expirationTime {
            self.exp = ExpirationClaim(value: expirationTime)
        }
    }

    // MARK: - JWTPayload Conformance

    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Verify expiration if present
        if let exp = exp {
            try exp.verifyNotExpired()
        }

        // Additional custom verification can be added here
    }
}

// MARK: - Extensions for JWT Claims

extension JWTRefreshToken {
    /// Create a JWTRefreshToken from an existing RefreshToken
    public init(from refreshToken: any RefreshToken, issuer: String, expirationTime: Date? = nil) {
        self.init(
            issuer: issuer,
            subject: refreshToken.userID ?? "",
            audience: refreshToken.clientID,
            expirationTime: expirationTime,
            scope: refreshToken.scopes?.joined(separator: " "),
            clientID: refreshToken.clientID
        )
    }
}
