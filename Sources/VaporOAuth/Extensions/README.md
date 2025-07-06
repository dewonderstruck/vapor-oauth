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

## Creating Custom Extensions

To create a new extension, implement the `OAuthExtension` protocol:

```swift
public struct MyCustomExtension: OAuthExtension {
    public let extensionID = "my_extension"
    public let extensionName = "My Custom Extension"
    public let specificationVersion = "1.0"
    
    public var modifiesAuthorizationRequest: Bool { true }
    public var modifiesTokenRequest: Bool { false }
    public var addsEndpoints: Bool { false }
    public var requiresConfiguration: Bool { false }
    
    public init() {}
    
    public func initialize(with oauth2: OAuth2) async throws {
        // Initialize your extension
    }
    
    public func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws -> AuthorizationRequestObject? {
        // Process authorization request
        return nil
    }
    
    public func processTokenRequest(_ request: Request) async throws -> Request? {
        // Process token request
        return nil
    }
    
    public func validateRequest(_ request: Request) async throws -> [OAuthExtensionError] {
        // Validate extension-specific parameters
        return []
    }
    
    public func getMetadata() -> [String: Any] {
        // Return extension metadata
        return [
            "extension_id": extensionID,
            "extension_name": extensionName,
            "specification_version": specificationVersion
        ]
    }
}
```

## Extension Points

### Authorization Request Processing

Extensions can process authorization requests after validation but before user consent.

### Token Request Processing

Extensions can process token requests before they are handled by the token handlers.

### Request Validation

Extensions can validate their specific parameters and return validation errors.

### Route Addition

Extensions can add new endpoints to the OAuth server.

## Error Handling

Extensions can throw `OAuthExtensionError` types:

- `invalidParameter` - Invalid parameter value
- `unsupportedExtension` - Extension not supported
- `extensionValidationFailed` - Extension validation failed
- `extensionProcessingFailed` - Extension processing failed
- `extensionInitializationFailed` - Extension initialization failed
- `extensionConfigurationError` - Extension configuration error

All errors include:
- Descriptive error messages
- Failure reasons
- Recovery suggestions
- Localized error descriptions

## Production Features

### Logging

All extensions include comprehensive logging:
- Info level for successful operations
- Warning level for validation issues
- Error level for failures
- Debug level for detailed processing

### Configuration

Extensions support flexible configuration:
- Custom validation rules
- Configurable limits
- Feature toggles
- Security settings

### Validation

Robust validation includes:
- Parameter format validation
- Business rule validation
- Security validation
- RFC compliance validation

### Error Recovery

Graceful error handling:
- Detailed error messages
- Recovery suggestions
- Fallback mechanisms
- Error categorization

## RFC Compliance

All extensions in this library are designed to be RFC compliant:

- **Error Handling** - Follows OAuth 2.0 error handling standards
- **Parameter Validation** - Validates parameters according to RFC specifications
- **Security** - Implements security considerations from relevant RFCs
- **Metadata** - Provides discovery endpoints for extension capabilities

## Best Practices

1. **RFC Compliance** - Always implement extensions according to the relevant RFC
2. **Idempotent Processing** - Extensions should be idempotent when processing requests
3. **Error Handling** - Always provide meaningful error messages with recovery suggestions
4. **Validation** - Validate all extension-specific parameters thoroughly
5. **Documentation** - Document your extension's behavior and requirements
6. **Testing** - Test your extension thoroughly with various scenarios
7. **Logging** - Include comprehensive logging for debugging and monitoring
8. **Configuration** - Make extensions configurable for different environments
9. **Security** - Implement proper security measures and validation
10. **Performance** - Ensure extensions don't significantly impact performance

## Future Extensions

The extension system is designed to support future OAuth 2.0 extensions:

- **Pushed Authorization Requests (PAR)** - RFC 9126
- **JWT Secured Authorization Requests (JAR)** - RFC 9101
- **OAuth 2.0 for Native Apps** - RFC 8252
- **OAuth 2.0 Device Authorization Grant** - RFC 8628 (already implemented in core)
- **OAuth 2.0 Authorization Server Metadata** - RFC 8414 (already implemented in core)

## References

- [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750) 