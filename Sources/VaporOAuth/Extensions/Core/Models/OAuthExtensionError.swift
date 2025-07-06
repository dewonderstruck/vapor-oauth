import Foundation

/// Errors that can be thrown by OAuth extensions
public enum OAuthExtensionError: Error, LocalizedError {
    case invalidParameter(String, String)  // parameter name, description
    case unsupportedExtension(String)
    case extensionValidationFailed(String)
    case extensionProcessingFailed(String)
    case extensionInitializationFailed(String)
    case extensionConfigurationError(String)
    case serverError(String)  // server-side error message

    public var errorDescription: String? {
        switch self {
        case .invalidParameter(let param, let description):
            return "Invalid parameter '\(param)': \(description)"
        case .unsupportedExtension(let extensionID):
            return "Unsupported extension: \(extensionID)"
        case .extensionValidationFailed(let message):
            return "Extension validation failed: \(message)"
        case .extensionProcessingFailed(let message):
            return "Extension processing failed: \(message)"
        case .extensionInitializationFailed(let message):
            return "Extension initialization failed: \(message)"
        case .extensionConfigurationError(let message):
            return "Extension configuration error: \(message)"
        case .serverError(let message):
            return "Server error: \(message)"
        }
    }

    public var failureReason: String? {
        switch self {
        case .invalidParameter(let param, _):
            return "Parameter '\(param)' is invalid"
        case .unsupportedExtension(let extensionID):
            return "Extension '\(extensionID)' is not supported"
        case .extensionValidationFailed:
            return "Extension validation failed"
        case .extensionProcessingFailed:
            return "Extension processing failed"
        case .extensionInitializationFailed:
            return "Extension initialization failed"
        case .extensionConfigurationError:
            return "Extension configuration error"
        case .serverError:
            return "Server error occurred"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .invalidParameter:
            return "Check the parameter format and ensure it meets the extension requirements"
        case .unsupportedExtension:
            return "Ensure the extension is properly registered and supported by this OAuth server"
        case .extensionValidationFailed:
            return "Review the extension configuration and ensure all required parameters are provided"
        case .extensionProcessingFailed:
            return "Check the extension implementation and ensure it handles the request correctly"
        case .extensionInitializationFailed:
            return "Verify the extension configuration and dependencies"
        case .extensionConfigurationError:
            return "Review the extension configuration and ensure all required settings are provided"
        case .serverError:
            return "Contact the server administrator or try again later"
        }
    }
}
