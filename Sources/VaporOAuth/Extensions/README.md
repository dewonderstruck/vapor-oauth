# OAuth 2.0 Extensions Framework

This directory contains the extensible OAuth 2.0 framework that allows you to add new OAuth 2.0 extensions without modifying the core functionality.

## Directory Structure

```
Extensions/
├── Core/                           # Core extension framework
│   ├── Models/
│   │   └── OAuthExtensionError.swift
│   ├── Protocols/
│   │   └── OAuthExtension.swift
│   └── Managers/
│       └── OAuthExtensionManager.swift
├── RAR/                           # Rich Authorization Requests
│   ├── Models/
│   ├── Protocols/
│   ├── RouteHandlers/
│   ├── Validators/
│   └── RichAuthorizationRequestsExtension.swift
├── PAR/                           # Pushed Authorization Requests
│   ├── Models/
│   ├── Protocols/
│   ├── RouteHandlers/
│   ├── Validators/
│   └── PushedAuthorizationRequestsExtension.swift
└── README.md                      # This file
```

## Overview

The extension system provides a production-ready, modular architecture for adding OAuth 2.0 extensions such as:

- **Rich Authorization Requests (RAR)** - RFC 9396
- **Pushed Authorization Requests (PAR)** - RFC 9126  
- **JWT Secured Authorization Requests (JAR)** - RFC 9101
- And other future extensions

## Architecture

### Core Components

1. **OAuthExtension Protocol** - Base protocol that all extensions must implement
2. **OAuthExtensionManager** - Manages registration and processing of extensions
3. **OAuthExtensionError** - Comprehensive error types for extension-specific errors

### Extension Lifecycle

1. **Registration** - Extensions are registered with the extension manager
2. **Initialization** - Extensions are initialized with the OAuth server configuration
3. **Processing** - Extensions process requests at various points in the OAuth flow
4. **Validation** - Extensions validate their specific parameters
5. **Route Addition** - Extensions can add new endpoints if needed

## Available Extensions

### Rich Authorization Requests (RAR) - RFC 9396

Enables fine-grained permission requests using the `authorization_details` parameter.

**Features:**
- JSON-based authorization details
- Type and action validation
- Extensible permission system
- RFC 9396 compliance

**Usage:**
```swift
let rarExtension = RichAuthorizationRequestsExtension()
extensionManager.register(rarExtension)
```

### Pushed Authorization Requests (PAR) - RFC 9126

Enables clients to push authorization request parameters to the server and receive a request URI.

**Features:**
- Request pushing to `/oauth/par` endpoint
- Request URI generation (`urn:ietf:params:oauth:request_uri:<identifier>`)
- Secure storage with expiration
- Replay protection
- Client authentication required
- RFC 9126 compliance

**Usage:**
```swift
let parExtension = PushedAuthorizationRequestsExtension()
extensionManager.register(parExtension)
```

**PAR Flow:**
1. Client pushes request to `/oauth/par`
2. Server returns `request_uri` and `expires_in`
3. Client uses `request_uri` in authorization flow

## Creating Custom Extensions

To create a new extension, implement the `OAuthExtension` protocol:

```swift
public struct MyCustomExtension: OAuthExtension {
    public let extensionID = "my-extension"
    public let extensionName = "My Custom Extension"
    public let specificationVersion = "1.0"
    
    public var modifiesAuthorizationRequest: Bool { true }
    public var modifiesTokenRequest: Bool { false }
    public var addsEndpoints: Bool { false }
    public var requiresConfiguration: Bool { false }
    
    public func initialize(with oauth2: OAuth2) async throws {
        // Initialize your extension
    }
    
    public func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws -> AuthorizationRequestObject? {
        // Process authorization requests
        return nil
    }
    
    public func validateRequest(_ request: Request) async throws -> [OAuthExtensionError] {
        // Validate extension-specific parameters
        return []
    }
    
    public func getMetadata() -> [String: Any] {
        // Return extension metadata
        return [:]
    }
}
```

## Extension Registration

Register extensions with the extension manager:

```swift
let extensionManager = OAuthExtensionManager()

// Register extensions
extensionManager.register(RichAuthorizationRequestsExtension())
extensionManager.register(PushedAuthorizationRequestsExtension())

// Add to OAuth2 server
let oauth2 = OAuth2(
    // ... other parameters
    extensionManager: extensionManager
)
```

## Extension Discovery

The framework provides centralized extension discovery:

```bash
# Get all registered extensions
GET /oauth/extensions/metadata

# Validate request parameters through all extensions
POST /oauth/extensions/validate
Content-Type: application/json

{
  "requestData": {
    "authorization_details": "[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]",
    "request_uri": "urn:ietf:params:oauth:request_uri:abc123"
  }
}
```

## Error Handling

Extensions use `OAuthExtensionError` for consistent error handling:

```swift
public enum OAuthExtensionError: Error, LocalizedError {
    case invalidParameter(String, String)
    case unsupportedExtension(String)
    case extensionValidationFailed(String)
    case extensionProcessingFailed(String)
    case extensionInitializationFailed(String)
    case extensionConfigurationError(String)
}
```

## Security Considerations

When implementing extensions:

1. **Input Validation** - Validate all extension-specific parameters
2. **Authentication** - Ensure proper client authentication where required
3. **Authorization** - Check client permissions for extension features
4. **Rate Limiting** - Apply rate limiting to prevent abuse
5. **Logging** - Log all extension operations for audit purposes
6. **Error Handling** - Provide secure error responses
7. **Data Protection** - Protect sensitive extension data
8. **Configuration** - Make extensions configurable for different environments
9. **Security** - Implement proper security measures and validation
10. **Performance** - Ensure extensions don't significantly impact performance

## Future Extensions

The extension system is designed to support future OAuth 2.0 extensions:

- **Pushed Authorization Requests (PAR)** - RFC 9126 ✅
- **JWT Secured Authorization Requests (JAR)** - RFC 9101
- **OAuth 2.0 for Native Apps** - RFC 8252
- **OAuth 2.0 Device Authorization Grant** - RFC 8628 (already implemented in core)
- **OAuth 2.0 Authorization Server Metadata** - RFC 8414 (already implemented in core)

## References

- [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [RFC 9126: OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396) 