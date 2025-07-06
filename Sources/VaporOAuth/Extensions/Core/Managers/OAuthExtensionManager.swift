import Foundation
import Vapor

/// Manager for OAuth extensions
public final class OAuthExtensionManager: @unchecked Sendable {
    private var extensions: [String: any OAuthExtension] = [:]
    private let logger: Logger

    public init(logger: Logger = Logger(label: "oauth-extensions")) {
        self.logger = logger
    }

    /// Register an extension with the manager
    /// - Parameter oauthExtension: The extension to register
    public func register(_ oauthExtension: some OAuthExtension) {
        extensions[oauthExtension.extensionID] = oauthExtension
        logger.info("Registered OAuth extension: \(oauthExtension.extensionName) (\(oauthExtension.extensionID))")
    }

    /// Get an extension by its ID
    /// - Parameter extensionID: The extension identifier
    /// - Returns: The extension if registered, nil otherwise
    public func getExtension(_ extensionID: String) -> (any OAuthExtension)? {
        return extensions[extensionID]
    }

    /// Get all registered extensions
    /// - Returns: Array of all registered extensions
    public func getAllExtensions() -> [any OAuthExtension] {
        return Array(extensions.values)
    }

    /// Get all extension metadata for discovery
    /// - Returns: Array of extension metadata dictionaries
    public func getAllExtensionMetadata() -> [[String: Any]] {
        return extensions.values.map { $0.getMetadata() }
    }

    /// Initialize all registered extensions
    /// - Parameter oauth2: The OAuth 2.0 server instance
    public func initializeExtensions(with oauth2: OAuth2) async throws {
        logger.info("Initializing \(extensions.count) OAuth extension(s)")

        for oauthExtension in extensions.values {
            do {
                try await oauthExtension.initialize(with: oauth2)
                logger.info("Successfully initialized extension: \(oauthExtension.extensionName)")
            } catch {
                logger.error("Failed to initialize extension \(oauthExtension.extensionName): \(error)")
                throw OAuthExtensionError.extensionInitializationFailed(
                    "Failed to initialize \(oauthExtension.extensionName): \(error.localizedDescription)")
            }
        }
    }

    /// Process validated authorization request through all extensions
    /// - Parameters:
    ///   - request: The incoming HTTP request
    ///   - authRequest: The validated authorization request object
    /// - Returns: Modified authorization request object
    public func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws
        -> AuthorizationRequestObject
    {
        var processedRequest = authRequest

        for oauthExtension in extensions.values where oauthExtension.modifiesAuthorizationRequest {
            do {
                if let modified = try await oauthExtension.processValidatedAuthorizationRequest(request, authRequest: processedRequest) {
                    processedRequest = modified
                    logger.debug("Extension \(oauthExtension.extensionName) modified authorization request")
                }
            } catch {
                logger.error("Extension \(oauthExtension.extensionName) failed to process authorization request: \(error)")
                throw OAuthExtensionError.extensionProcessingFailed(
                    "Extension \(oauthExtension.extensionName) failed: \(error.localizedDescription)")
            }
        }

        return processedRequest
    }

    /// Process token request through all extensions
    /// - Parameters:
    ///   - request: The incoming HTTP request
    /// - Returns: Modified request
    public func processTokenRequest(_ request: Request) async throws -> Request {
        var processedRequest = request

        for oauthExtension in extensions.values where oauthExtension.modifiesTokenRequest {
            do {
                if let modified = try await oauthExtension.processTokenRequest(processedRequest) {
                    processedRequest = modified
                    logger.debug("Extension \(oauthExtension.extensionName) modified token request")
                }
            } catch {
                logger.error("Extension \(oauthExtension.extensionName) failed to process token request: \(error)")
                throw OAuthExtensionError.extensionProcessingFailed(
                    "Extension \(oauthExtension.extensionName) failed: \(error.localizedDescription)")
            }
        }

        return processedRequest
    }

    /// Add routes for all extensions
    /// - Parameter app: The Vapor application instance
    public func addExtensionRoutes(to app: Application) async throws {
        logger.info("Adding routes for \(extensions.values.filter { $0.addsEndpoints }.count) extension(s)")

        // Add centralized extension discovery endpoint
        app.get("oauth", "extensions", "metadata") { [weak self] request in
            guard let self = self else {
                throw Abort(.internalServerError, reason: "Extension manager not available")
            }
            return try await self.handleExtensionsMetadataRequest(request)
        }

        // Add centralized extension validation endpoint
        app.post("oauth", "extensions", "validate") { [weak self] request in
            guard let self = self else {
                throw Abort(.internalServerError, reason: "Extension manager not available")
            }
            return try await self.handleExtensionsValidationRequest(request)
        }

        for oauthExtension in extensions.values where oauthExtension.addsEndpoints {
            do {
                try await oauthExtension.addRoutes(to: app)
                logger.info("Successfully added routes for extension: \(oauthExtension.extensionName)")
            } catch {
                logger.error("Failed to add routes for extension \(oauthExtension.extensionName): \(error)")
                throw OAuthExtensionError.extensionProcessingFailed(
                    "Failed to add routes for \(oauthExtension.extensionName): \(error.localizedDescription)")
            }
        }
    }

    /// Handle extension metadata discovery request
    /// - Parameter request: The incoming HTTP request
    /// - Returns: Extension metadata response
    public func handleExtensionsMetadataRequest(_ request: Request) async throws -> ExtensionsMetadataResponse {
        logger.info("Handling extension metadata request")

        let extensionsList = getAllExtensions().map { ext in
            ExtensionInfo(
                id: ext.extensionID,
                name: ext.extensionName,
                specificationVersion: ext.specificationVersion,
                modifiesAuthorizationRequest: ext.modifiesAuthorizationRequest,
                modifiesTokenRequest: ext.modifiesTokenRequest,
                addsEndpoints: ext.addsEndpoints,
                requiresConfiguration: ext.requiresConfiguration,
                metadata: ext.getMetadata()
            )
        }

        return ExtensionsMetadataResponse(
            extensions: extensionsList,
            totalExtensions: extensionsList.count
        )
    }

    /// Handle extension validation request
    /// - Parameter request: The incoming HTTP request
    /// - Returns: Validation response
    private func handleExtensionsValidationRequest(_ request: Request) async throws -> ExtensionsValidationResponse {
        logger.info("Handling extension validation request")

        let validationRequest = try request.content.decode(ExtensionsValidationRequest.self)

        var allErrors: [ExtensionValidationError] = []

        // Encode requestData into request.content for validation
        try request.content.encode(validationRequest.requestData)

        // Validate through all extensions
        for oauthExtension in extensions.values {
            do {
                let extensionErrors = try await oauthExtension.validateRequest(request)

                if !extensionErrors.isEmpty {
                    allErrors.append(
                        contentsOf: extensionErrors.map { error in
                            ExtensionValidationError(
                                extensionID: oauthExtension.extensionID,
                                extensionName: oauthExtension.extensionName,
                                error: error.localizedDescription,
                                errorType: error.failureReason ?? "validation_error"
                            )
                        })
                }
            } catch {
                allErrors.append(
                    ExtensionValidationError(
                        extensionID: oauthExtension.extensionID,
                        extensionName: oauthExtension.extensionName,
                        error: error.localizedDescription,
                        errorType: "validation_failed"
                    ))
            }
        }

        return ExtensionsValidationResponse(
            valid: allErrors.isEmpty,
            errors: allErrors,
            validatedExtensions: extensions.values.map { $0.extensionID }
        )
    }

    /// Validate request through all extensions
    /// - Parameter request: The incoming HTTP request
    /// - Returns: Array of all validation errors
    public func validateRequest(_ request: Request) async throws -> [OAuthExtensionError] {
        var errors: [OAuthExtensionError] = []

        for oauthExtension in extensions.values {
            do {
                let extensionErrors = try await oauthExtension.validateRequest(request)
                errors.append(contentsOf: extensionErrors)

                if !extensionErrors.isEmpty {
                    logger.warning("Extension \(oauthExtension.extensionName) returned \(extensionErrors.count) validation error(s)")
                }
            } catch {
                logger.error("Extension \(oauthExtension.extensionName) failed during validation: \(error)")
                errors.append(
                    .extensionValidationFailed("Extension \(oauthExtension.extensionName) validation failed: \(error.localizedDescription)")
                )
            }
        }

        return errors
    }

    /// Check if any extension requires configuration
    /// - Returns: True if any extension requires configuration
    public func hasExtensionsRequiringConfiguration() -> Bool {
        return extensions.values.contains { $0.requiresConfiguration }
    }

    /// Get extensions that require configuration
    /// - Returns: Array of extensions that require configuration
    public func getExtensionsRequiringConfiguration() -> [any OAuthExtension] {
        return extensions.values.filter { $0.requiresConfiguration }
    }
}

// MARK: - Application Extensions

extension Application {
    struct OAuthExtensionManagerKey: StorageKey {
        typealias Value = OAuthExtensionManager
    }

    public var oauthExtensions: OAuthExtensionManager {
        get {
            if let manager = storage[OAuthExtensionManagerKey.self] {
                return manager
            }
            let manager = OAuthExtensionManager()
            storage[OAuthExtensionManagerKey.self] = manager
            return manager
        }
        set {
            storage[OAuthExtensionManagerKey.self] = newValue
        }
    }
}

extension Request {
    public var oauthExtensions: OAuthExtensionManager { application.oauthExtensions }
}

// MARK: - Extension Discovery and Validation Models

/// Information about a registered extension
public struct ExtensionInfo: Codable, Sendable {
    public let id: String
    public let name: String
    public let specificationVersion: String
    public let modifiesAuthorizationRequest: Bool
    public let modifiesTokenRequest: Bool
    public let addsEndpoints: Bool
    public let requiresConfiguration: Bool
    public let metadata: [String: Any]

    public init(
        id: String,
        name: String,
        specificationVersion: String,
        modifiesAuthorizationRequest: Bool,
        modifiesTokenRequest: Bool,
        addsEndpoints: Bool,
        requiresConfiguration: Bool,
        metadata: [String: Any]
    ) {
        self.id = id
        self.name = name
        self.specificationVersion = specificationVersion
        self.modifiesAuthorizationRequest = modifiesAuthorizationRequest
        self.modifiesTokenRequest = modifiesTokenRequest
        self.addsEndpoints = addsEndpoints
        self.requiresConfiguration = requiresConfiguration
        self.metadata = metadata
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, specificationVersion, modifiesAuthorizationRequest, modifiesTokenRequest, addsEndpoints, requiresConfiguration,
            metadata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        specificationVersion = try container.decode(String.self, forKey: .specificationVersion)
        modifiesAuthorizationRequest = try container.decode(Bool.self, forKey: .modifiesAuthorizationRequest)
        modifiesTokenRequest = try container.decode(Bool.self, forKey: .modifiesTokenRequest)
        addsEndpoints = try container.decode(Bool.self, forKey: .addsEndpoints)
        requiresConfiguration = try container.decode(Bool.self, forKey: .requiresConfiguration)
        metadata = [:]  // Metadata is not decoded as it's dynamic
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(specificationVersion, forKey: .specificationVersion)
        try container.encode(modifiesAuthorizationRequest, forKey: .modifiesAuthorizationRequest)
        try container.encode(modifiesTokenRequest, forKey: .modifiesTokenRequest)
        try container.encode(addsEndpoints, forKey: .addsEndpoints)
        try container.encode(requiresConfiguration, forKey: .requiresConfiguration)
        // Metadata is not encoded as it's dynamic
    }
}

/// Response for extension metadata discovery
public struct ExtensionsMetadataResponse: Codable, Sendable, AsyncResponseEncodable {
    public let extensions: [ExtensionInfo]
    public let totalExtensions: Int

    public init(extensions: [ExtensionInfo], totalExtensions: Int) {
        self.extensions = extensions
        self.totalExtensions = totalExtensions
    }

    public func encodeResponse(for request: Request) async throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        let response = Response(body: .init(data: data))
        response.headers.replaceOrAdd(name: .contentType, value: "application/json")
        return response
    }
}

/// Request for extension validation
public struct ExtensionsValidationRequest: Codable, Sendable {
    public let requestData: [String: String]  // Key-value pairs to validate

    public init(requestData: [String: String]) {
        self.requestData = requestData
    }
}

/// Validation error from an extension
public struct ExtensionValidationError: Codable, Sendable {
    public let extensionID: String
    public let extensionName: String
    public let error: String
    public let errorType: String

    public init(extensionID: String, extensionName: String, error: String, errorType: String) {
        self.extensionID = extensionID
        self.extensionName = extensionName
        self.error = error
        self.errorType = errorType
    }
}

/// Response for extension validation
public struct ExtensionsValidationResponse: Codable, Sendable, AsyncResponseEncodable {
    public let valid: Bool
    public let errors: [ExtensionValidationError]
    public let validatedExtensions: [String]

    public init(valid: Bool, errors: [ExtensionValidationError], validatedExtensions: [String]) {
        self.valid = valid
        self.errors = errors
        self.validatedExtensions = validatedExtensions
    }

    public func encodeResponse(for request: Request) async throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        let response = Response(body: .init(data: data))
        response.headers.replaceOrAdd(name: .contentType, value: "application/json")
        return response
    }
}
