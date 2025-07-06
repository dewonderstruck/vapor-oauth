# Rich Authorization Requests (RAR) Extension

OAuth 2.0 Rich Authorization Requests (RAR) extension implementing [RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396).

## Overview

The Rich Authorization Requests (RAR) extension fundamentally enhances OAuth 2.0 by enabling clients to request fine-grained, context-aware permissions during authorization flows. Unlike traditional OAuth 2.0 scopes that are simple strings, RAR introduces a structured JSON-based approach to permission specification that allows for precise control over what resources and actions a client can access.

This extension addresses the limitations of traditional OAuth 2.0 scopes by providing a standardized way to express complex authorization requirements. Instead of using broad scope strings like "read write", clients can now specify exactly what they need: which specific resources, what actions they want to perform, and under what conditions.

The RAR extension operates by intercepting and processing the `authorization_details` parameter in OAuth 2.0 authorization and token requests. This parameter contains a JSON array of authorization detail objects, each describing a specific permission requirement with structured data including type, actions, locations, and custom data.

## Technical Architecture

The RAR extension is built on a modular architecture that separates concerns and provides extensibility. The core components work together to provide a robust, RFC-compliant implementation:

**Extension Core**: The `RichAuthorizationRequestsExtension` class implements the `OAuthExtension` protocol and serves as the main entry point. It coordinates validation, processing, and metadata generation while maintaining RFC 9396 compliance.

**Validation Engine**: The `RARValidator` provides comprehensive validation of authorization details according to RFC 9396 rules. It enforces type safety, validates URIs, checks limits, and ensures all required fields are present and properly formatted.

**Type System**: A flexible type registry system allows for both predefined RAR types (like payment_initiation, account_access) and custom types. The `RARTypeRegistry` protocol enables applications to define domain-specific authorization types while maintaining interoperability.

**Builder Pattern**: The `AuthorizationDetailBuilder` provides a fluent API for constructing authorization details, making it easy to create complex permission structures programmatically while ensuring type safety and validation.

## Installation and Setup

The RAR extension is included with the VaporOAuth library and requires no additional dependencies. To integrate it into your OAuth 2.0 server, you need to register it with the extension manager and configure it according to your application's requirements.

The extension integrates seamlessly with the existing VaporOAuth architecture, hooking into the authorization and token request processing pipelines. When registered, it automatically validates `authorization_details` parameters and provides metadata through the centralized extension discovery system.

## Configuration and Customization

The RAR extension provides extensive configuration options to adapt to different use cases and security requirements. The `RARConfiguration` struct allows you to control validation behavior, set limits, and restrict allowed types and actions.

**Security Configuration**: You can restrict the extension to only allow specific RAR types and actions, preventing clients from requesting permissions outside your application's domain. This is particularly important for financial applications where strict control over payment-related permissions is required.

**Validation Settings**: The extension can be configured to validate URIs in location fields, enforce maximum limits on the number of authorization details, and control whether custom types are allowed. These settings help maintain security while providing flexibility.

**Type Registry Integration**: For applications with domain-specific requirements, you can implement custom type registries that define application-specific authorization types and actions. This allows for rich, contextual permission models while maintaining RFC compliance.

## Usage Patterns and Examples

The RAR extension supports various usage patterns depending on your application's needs. Here are comprehensive examples showing how to implement different scenarios:

### Payment Processing Scenario

For financial applications, RAR enables precise control over payment operations. You can specify exactly what type of payment, what actions are allowed, and what data is required:

```swift
// Create a payment initiation authorization detail
var builder = AuthorizationDetailBuilder(type: .paymentInitiation)
builder = builder.actions([.initiate, .status, .cancel])
    .location("https://api.example.com/payments")
    .data("instructedAmount", [
        "currency": "EUR",
        "amount": "123.50"
    ])
    .data("creditorAccount", [
        "iban": "DE89370400440532013000"
    ])

let authDetails = [builder.build()]

// Encode for use in authorization request
let encoder = JSONEncoder()
let data = try encoder.encode(authDetails)
let encoded = String(data: data, encoding: .utf8) ?? ""
```

This creates a structured permission that allows the client to initiate, check status, and cancel payments with specific amount and account information.

### Account Access Scenario

For applications that need to access user accounts, RAR provides granular control over what account information can be accessed:

```swift
// Create an account access authorization detail
let accountDetail = AuthorizationDetailBuilder(type: .accountAccess)
    .actions([.read])
    .location("https://api.example.com/accounts")
    .data("accountIds", ["12345", "67890"])
    .data("dataTypes", ["balance", "transactions"])
    .build()
```

This specifies that the client can read specific accounts and access only balance and transaction data.

### Data Access with Retention Policies

For applications handling sensitive data, RAR can specify retention policies and data handling requirements:

```swift
// Create a data access authorization detail with retention policy
let dataDetail = AuthorizationDetailBuilder(type: .dataAccess)
    .actions([.read, .write])
    .location("https://api.example.com/data")
    .data("dataTypes", ["personal", "financial"])
    .data("retentionPeriod", "30d")
    .data("encryptionRequired", true)
    .build()
```

This ensures that data access includes specific retention and encryption requirements.

## Authorization Request Integration

When using RAR in authorization requests, the `authorization_details` parameter is included as a URL-encoded JSON string. The extension automatically validates this parameter and processes the authorization details according to RFC 9396.

The authorization request flow integrates the RAR extension at multiple points:

1. **Parameter Extraction**: The extension extracts and decodes the `authorization_details` parameter from the request
2. **Validation**: Each authorization detail is validated against the configured rules and RFC 9396 requirements
3. **Processing**: Valid authorization details are processed and can be used to modify the authorization flow
4. **Error Handling**: Invalid authorization details result in appropriate OAuth 2.0 error responses

## Token Request Processing

For token requests, the `authorization_details` parameter is included in the form data. The extension validates that the authorization details in the token request match those from the original authorization request, ensuring consistency and preventing privilege escalation.

The token request processing ensures that:
- Authorization details are present and valid
- The details match those from the authorization request
- The token is issued with the appropriate permissions
- Any custom data is preserved for later use

## Extension Discovery and Validation

The VaporOAuth extension framework provides centralized endpoints for discovering and validating extensions, including comprehensive RAR-specific information.

### Metadata Discovery

The `/oauth/extensions/metadata` endpoint returns detailed information about all registered extensions, including RAR configuration, supported types and actions, usage examples, and validation rules. This enables clients to discover what RAR capabilities are available and how to use them.

The metadata includes:
- Extension identification and version information
- Configuration details including validation settings
- Complete list of supported RAR types with descriptions
- Available actions and their meanings
- Usage examples for common scenarios
- Validation rules and requirements

### Validation Endpoint

The `/oauth/extensions/validate` endpoint allows clients to validate authorization details before making actual requests. This is particularly useful for client applications that want to ensure their authorization details are correctly formatted and will be accepted by the server.

The validation endpoint:
- Accepts authorization details in the same format as actual requests
- Validates against all registered extensions
- Returns detailed error information for invalid requests
- Provides feedback on what needs to be corrected

## RFC 9396 Compliance

The RAR extension is fully compliant with RFC 9396, implementing all required functionality and following the specification's guidelines for error handling, parameter usage, and validation.

### Parameter Usage Compliance

The extension correctly implements the `authorization_details` parameter as specified in RFC 9396:
- Accepts the parameter in both authorization and token requests
- Processes JSON arrays of authorization detail objects
- Enforces the required `type` field for each authorization detail
- Handles optional fields (`actions`, `locations`, `data`, `custom`) appropriately
- Validates parameter format and content according to RFC rules

### Error Handling Compliance

Error handling follows RFC 9396 and OAuth 2.0 standards:
- Uses `invalid_request` for malformed `authorization_details` parameters
- Uses `invalid_scope` for invalid authorization detail types or actions
- Provides clear error descriptions to help clients understand and fix issues
- Maintains compatibility with existing OAuth 2.0 error handling

### No Custom Endpoints

As specified in RFC 9396, the RAR extension does not define custom endpoints. Instead, it integrates with existing OAuth 2.0 flows and uses the centralized extension framework for discovery and validation. This ensures interoperability and prevents fragmentation of the OAuth ecosystem.

## Predefined Types and Actions

The RAR extension includes a comprehensive set of predefined types and actions that cover common use cases in modern applications.

### Financial Types

**Payment Initiation**: Enables clients to initiate payment transactions with specific amounts, currencies, and recipient information. This type is commonly used in financial applications and open banking scenarios.

**Account Access**: Allows access to account information including balances, transactions, and account details. This is essential for financial aggregation and account management applications.

**Funds Confirmation**: Enables checking account balances and fund availability without initiating transactions. This is useful for pre-authorization scenarios.

**Domestic and International Payments**: Specialized types for different payment scenarios with appropriate validation and security requirements.

### Data Access Types

**Account Information**: Provides access to account-related data without transaction capabilities. This is useful for read-only financial applications.

**File Access**: Enables access to files and documents with specific permissions for reading, writing, or downloading.

**Data Access**: General-purpose data access with configurable permissions and retention policies.

### Card Payment Types

**Card Payment**: Enables card-based payment operations with appropriate security controls and validation.

### Actions and Operations

The extension provides a rich set of actions that can be combined with types to create precise permission specifications:

**Read Operations**: Basic read access to resources and data
**Write Operations**: Ability to modify or create resources
**Initiate Operations**: Starting processes or transactions
**Status Operations**: Checking the status of ongoing operations
**Cancel Operations**: Stopping or canceling operations
**Download/Upload Operations**: File transfer capabilities
**Update Operations**: Modifying existing resources
**Execute Operations**: Running processes or scripts

## Custom Types and Actions

The RAR extension's type system is designed for extensibility, allowing applications to define domain-specific authorization types and actions while maintaining RFC compliance.

### Implementing Custom Types

Custom types should implement the `RARTypeProtocol` and provide meaningful descriptions and validation rules:

```swift
enum CustomRARType: String, RARTypeProtocol {
    case documentAccess = "document_access"
    case userProfile = "user_profile"
    case auditLog = "audit_log"
    
    var description: String {
        switch self {
        case .documentAccess: return "Document Access and Management"
        case .userProfile: return "User Profile Information"
        case .auditLog: return "Audit Log Access"
        }
    }
    
    var requiresValidation: Bool {
        switch self {
        case .documentAccess: return true
        case .userProfile: return false
        case .auditLog: return true
        }
    }
    
    var defaultActions: [String] {
        switch self {
        case .documentAccess: return [RARAction.read.rawValue, RARAction.write.rawValue]
        case .userProfile: return [RARAction.read.rawValue]
        case .auditLog: return [RARAction.read.rawValue]
        }
    }
}
```

### Custom Actions

Custom actions should implement the `RARActionProtocol` and provide clear descriptions:

```swift
enum CustomRARAction: String, RARActionProtocol {
    case share = "share"
    case archive = "archive"
    case export = "export"
    
    var description: String {
        switch self {
        case .share: return "Share with other users"
        case .archive: return "Archive for long-term storage"
        case .export: return "Export data in various formats"
        }
    }
    
    var requiresSpecialPermission: Bool {
        switch self {
        case .share: return true
        case .archive: return false
        case .export: return true
        }
    }
}
```

### Custom Type Registries

Custom type registries implement the `RARTypeRegistry` protocol to provide type and action management:

```swift
struct CustomRARTypeRegistry: RARTypeRegistry {
    typealias RegistryType = CustomRARType
    typealias RegistryAction = CustomRARAction
    
    func registerCustomType(_ type: String) -> CustomRARType? {
        return CustomRARType(rawValue: type)
    }
    
    func isTypeRegistered(_ type: String) -> Bool {
        return CustomRARType(rawValue: type) != nil
    }
    
    func getAllTypes() -> [CustomRARType] {
        return Array(CustomRARType.allCases)
    }
    
    func getAllActions() -> [CustomRARAction] {
        return Array(CustomRARAction.allCases)
    }
}
```

## Error Handling and Validation

The RAR extension provides comprehensive error handling that helps clients understand and fix issues with their authorization requests.

### Validation Rules

The extension enforces several validation rules to ensure RFC compliance and security:

**Required Fields**: Each authorization detail must have a non-empty `type` field as specified in RFC 9396. This is the minimum requirement for any authorization detail.

**Type Validation**: Types must be either predefined in the registry or allowed if custom types are enabled. This prevents clients from requesting unknown or unauthorized permission types.

**Action Validation**: Actions must be predefined or allowed if custom actions are enabled. This ensures that only valid operations can be requested.

**Location Validation**: When URI validation is enabled, location fields must contain valid URIs. This prevents injection attacks and ensures proper resource identification.

**Limits Enforcement**: The number of authorization details must not exceed the configured maximum. This prevents abuse and ensures reasonable request sizes.

**Empty Value Prevention**: Actions and locations arrays must not contain empty values, ensuring data quality and preventing ambiguous requests.

### Error Types and Responses

The extension returns specific error types to help clients understand what went wrong:

**Invalid Request Errors**: Occur when the `authorization_details` parameter is malformed, missing required fields, or contains invalid JSON.

**Invalid Scope Errors**: Occur when authorization detail types or actions are not allowed by the current configuration.

**Server Errors**: Occur when internal validation processes fail or unexpected errors occur during processing.

### Error Response Format

Error responses follow OAuth 2.0 standards and include detailed information:

```json
{
  "error": "invalid_request",
  "error_description": "Invalid authorization_details format: Authorization detail at index 0 has empty type",
  "error_uri": "https://example.com/oauth/errors/invalid_request"
}
```

## Security Considerations

Implementing RAR requires careful attention to security considerations to ensure that the enhanced permission system doesn't introduce vulnerabilities.

### Input Validation

All `authorization_details` parameters must be thoroughly validated before processing. The extension provides comprehensive validation, but applications should also implement additional checks specific to their domain.

**JSON Validation**: Ensure that the authorization details are valid JSON and conform to the expected structure.

**Type Safety**: Validate that all types and actions are allowed according to your application's security policy.

**Data Validation**: Validate any custom data included in authorization details to prevent injection attacks.

### Type Restrictions

Consider restricting allowed types to only those relevant to your application domain. This prevents clients from requesting permissions outside your intended scope.

**Domain-Specific Types**: Define types that are specific to your application's functionality and security requirements.

**Action Limitations**: Limit available actions to those that your application actually supports and can safely execute.

**Custom Type Validation**: If allowing custom types, implement additional validation to ensure they don't introduce security risks.

### URI Validation

When URI validation is enabled, ensure that location URIs are properly validated to prevent security issues:

**Scheme Validation**: Only allow secure schemes (https) for production applications.

**Domain Validation**: Ensure that URIs point to authorized domains and resources.

**Path Validation**: Validate URI paths to prevent directory traversal attacks.

### Logging and Monitoring

Implement comprehensive logging for all RAR-related operations to enable security monitoring and audit trails.

**Request Logging**: Log all authorization requests that include RAR parameters for security analysis.

**Validation Logging**: Log validation failures to identify potential attacks or misconfigurations.

**Access Logging**: Log when RAR permissions are used to access resources for audit purposes.

## Testing and Validation

The RAR extension includes comprehensive tests that validate RFC compliance and ensure proper functionality.

### Test Coverage

The test suite covers:
- RFC 9396 compliance validation
- Parameter parsing and validation
- Error handling and response generation
- Type system functionality
- Builder pattern usage
- Extension integration
- Custom type and action support

### Running Tests

To run the RAR-specific tests:

```bash
swift test --filter RAR
```

To run all tests including RAR:

```bash
swift test
```

### Test Scenarios

The test suite includes scenarios for:
- Valid authorization details with various configurations
- Invalid authorization details to test error handling
- Malformed JSON to test parsing robustness
- Custom types and actions to test extensibility
- Extension discovery and validation endpoints
- Integration with the broader OAuth 2.0 flow

## Integration Examples

Here are comprehensive examples showing how to integrate the RAR extension into different types of applications.

### Financial Application Integration

For a financial application that needs to support open banking and payment initiation:

```swift
// Configure RAR for financial use case
let financialConfig = RARConfiguration(
    allowCustomTypes: false,
    maxAuthorizationDetails: 5,
    validateURIs: true,
    allowedTypes: [.paymentInitiation, .accountAccess, .fundConfirmation],
    allowedActions: [.read, .initiate, .status, .cancel],
    typeRegistry: DefaultRARTypeRegistry()
)

// Register the extension
var extensionManager = OAuthExtensionManager()
extensionManager.register(RichAuthorizationRequestsExtension(configuration: financialConfig))

// Create OAuth server with extensions
let oauth2 = OAuth2(
    tokenManager: yourTokenManager,
    clientRetriever: yourClientRetriever,
    oAuthHelper: yourOAuthHelper,
    extensionManager: extensionManager
)

app.lifecycle.use(oauth2)
```

### Data Access Application Integration

For an application that provides data access with retention policies:

```swift
// Configure RAR for data access
let dataConfig = RARConfiguration(
    allowCustomTypes: true,
    maxAuthorizationDetails: 10,
    validateURIs: true,
    allowedTypes: [.dataAccess, .fileAccess],
    allowedActions: [.read, .write, .download, .upload],
    typeRegistry: CustomDataRARTypeRegistry()
)

// Register with custom types
extensionManager.register(RichAuthorizationRequestsExtension(configuration: dataConfig))
```

### Healthcare Application Integration

For a healthcare application with strict privacy requirements:

```swift
// Configure RAR for healthcare
let healthcareConfig = RARConfiguration(
    allowCustomTypes: true,
    maxAuthorizationDetails: 3,
    validateURIs: true,
    allowedTypes: [.dataAccess, .fileAccess],
    allowedActions: [.read, .write],
    typeRegistry: HealthcareRARTypeRegistry()
)

// Register with healthcare-specific types
extensionManager.register(RichAuthorizationRequestsExtension(configuration: healthcareConfig))
```

## Troubleshooting

Common issues and their solutions when working with the RAR extension.

### Validation Errors

**"Invalid authorization_details format"**: Check that the JSON is properly formatted and URL-encoded when used in authorization requests.

**"Authorization detail at index X has empty type"**: Ensure that each authorization detail has a non-empty `type` field.

**"Type 'X' is not allowed"**: Verify that the type is either predefined or allowed in your configuration.

**"Action 'X' is not allowed"**: Check that the action is either predefined or allowed in your configuration.

### Configuration Issues

**Extensions not being registered**: Ensure that you're calling `addExtensionRoutes(to: app)` after registering extensions.

**Metadata endpoint returning 404**: Verify that the extension manager is properly configured and routes are added.

**Validation endpoint not working**: Check that the request format includes the `requestData` wrapper object.

### Performance Issues

**Slow validation**: Consider reducing the number of authorization details or optimizing custom validation logic.

**Memory usage**: Review custom type registries and ensure they're not holding unnecessary references.

**High CPU usage**: Check for inefficient validation rules or excessive logging.

## References and Resources

- [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)
- [OAuth 2.0 Extensions](https://oauth.net/2/extensions/)
- [VaporOAuth Extensions Framework](../README.md)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Open Banking RAR Profiles](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937951489/Dynamic+Client+Registration+Specification+-+v3.3) 