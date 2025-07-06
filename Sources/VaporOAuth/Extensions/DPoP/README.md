# OAuth 2.0 Demonstrating Proof of Possession (DPoP) Extension

Implements [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449).

## Features

- **Proof of Possession**: Clients demonstrate possession of private keys through DPoP tokens
- **Request Binding**: DPoP tokens are bound to specific HTTP methods and URIs
- **Replay Protection**: Nonce-based protection against replay attacks
- **Access Token Binding**: Binds access tokens to DPoP keys for enhanced security

## Usage

```swift
// Register the extension
let dpopExtension = DemonstratingProofOfPossessionExtension()
let extensionManager = OAuthExtensionManager()
extensionManager.register(dpopExtension)

// Add to OAuth2 server
let oauth2 = OAuth2(
    extensionManager: extensionManager
)
```

## Endpoints

- `GET /oauth/dpop_nonce`: Provides DPoP nonces for replay protection

## RFC 9449 Compliance

- DPoP token validation and verification
- Nonce management for replay protection
- Access token binding to DPoP keys
- Comprehensive error handling 