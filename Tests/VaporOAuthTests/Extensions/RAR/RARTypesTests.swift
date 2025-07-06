import Vapor
import XCTest

@testable import VaporOAuth

final class RARTypesTests: XCTestCase {

    // MARK: - RARType Tests

    func testRARTypeConformance() {
        // Test that RARType conforms to RARTypeProtocol
        let paymentType = RARType.paymentInitiation
        XCTAssertEqual(paymentType.rawValue, "payment_initiation")
        XCTAssertEqual(paymentType.description, "Payment Initiation")
        XCTAssertTrue(paymentType.requiresValidation)
        XCTAssertEqual(paymentType.defaultActions, ["initiate", "status", "cancel"])

        let accountType = RARType.accountAccess
        XCTAssertEqual(accountType.rawValue, "account_access")
        XCTAssertEqual(accountType.description, "Account Access")
        XCTAssertFalse(accountType.requiresValidation)
        XCTAssertEqual(accountType.defaultActions, ["read"])
    }

    func testRARActionConformance() {
        // Test that RARAction conforms to RARActionProtocol
        let readAction = RARAction.read
        XCTAssertEqual(readAction.rawValue, "read")
        XCTAssertEqual(readAction.description, "Read access")
        XCTAssertFalse(readAction.requiresSpecialPermission)

        let deleteAction = RARAction.delete
        XCTAssertEqual(deleteAction.rawValue, "delete")
        XCTAssertEqual(deleteAction.description, "Delete access")
        XCTAssertTrue(deleteAction.requiresSpecialPermission)
    }

    func testRARTypeRegistry() {
        let registry = DefaultRARTypeRegistry()

        // Test type registration
        XCTAssertTrue(registry.isTypeRegistered("payment_initiation"))
        XCTAssertTrue(registry.isTypeRegistered("account_access"))
        XCTAssertFalse(registry.isTypeRegistered("nonexistent_type"))

        // Test that actions are not registered as types
        XCTAssertFalse(registry.isTypeRegistered("read"))
        XCTAssertFalse(registry.isTypeRegistered("write"))

        // Test getting all types and actions
        let allTypes = registry.getAllTypes()
        XCTAssertGreaterThan(allTypes.count, 0)
        XCTAssertTrue(allTypes.contains(.paymentInitiation))
        XCTAssertTrue(allTypes.contains(.accountAccess))

        let allActions = registry.getAllActions()
        XCTAssertGreaterThan(allActions.count, 0)
        XCTAssertTrue(allActions.contains(.read))
        XCTAssertTrue(allActions.contains(.write))
    }

    // MARK: - Configuration Tests

    func testRARConfiguration() {
        let registry = DefaultRARTypeRegistry()
        let config = RARConfiguration(
            allowCustomTypes: true,
            maxAuthorizationDetails: 5,
            validateURIs: true,
            allowedTypes: [.paymentInitiation, .accountAccess],
            allowedActions: [.read, .write],
            typeRegistry: registry
        )

        XCTAssertTrue(config.allowCustomTypes)
        XCTAssertEqual(config.maxAuthorizationDetails, 5)
        XCTAssertTrue(config.validateURIs)
        XCTAssertEqual(config.allowedTypes?.count, 2)
        XCTAssertEqual(config.allowedActions?.count, 2)
        XCTAssertEqual(config.typeRegistry.getAllTypes().count, registry.getAllTypes().count)
    }

    func testStrictConfiguration() {
        let registry = DefaultRARTypeRegistry()
        let strictConfig = RARConfiguration.strict(
            allowedTypes: [.paymentInitiation],
            allowedActions: [.initiate],
            registry: registry
        )

        XCTAssertFalse(strictConfig.allowCustomTypes)
        XCTAssertEqual(strictConfig.maxAuthorizationDetails, 5)
        XCTAssertTrue(strictConfig.validateURIs)
        XCTAssertEqual(strictConfig.allowedTypes?.count, 1)
        XCTAssertEqual(strictConfig.allowedActions?.count, 1)
    }

    func testDefaultConfiguration() {
        let config = RARConfiguration.default
        XCTAssertTrue(config.allowCustomTypes)
        XCTAssertEqual(config.maxAuthorizationDetails, 10)
        XCTAssertTrue(config.validateURIs)
        XCTAssertNil(config.allowedTypes)  // All types allowed
        XCTAssertNil(config.allowedActions)  // All actions allowed
    }

    // MARK: - Custom Types Tests

    func testCustomRARTypes() {
        let customType = CustomRARType.documentAccess
        XCTAssertEqual(customType.rawValue, "document_access")
        XCTAssertEqual(customType.description, "Document Access")
        XCTAssertTrue(customType.requiresValidation)
        XCTAssertEqual(customType.defaultActions, ["read", "download"])

        let customAction = CustomRARAction.download
        XCTAssertEqual(customAction.rawValue, "download")
        XCTAssertEqual(customAction.description, "Download files")
        XCTAssertFalse(customAction.requiresSpecialPermission)
    }

    func testCustomRARTypeRegistry() {
        let registry = CustomRARTypeRegistry()

        XCTAssertTrue(registry.isTypeRegistered("document_access"))
        XCTAssertTrue(registry.isTypeRegistered("user_profile"))
        XCTAssertFalse(registry.isTypeRegistered("nonexistent_type"))

        let allTypes = registry.getAllTypes()
        XCTAssertEqual(allTypes.count, 4)  // documentAccess, userProfile, notificationSettings, apiAccess
        XCTAssertTrue(allTypes.contains(.documentAccess))
        XCTAssertTrue(allTypes.contains(.userProfile))

        let allActions = registry.getAllActions()
        XCTAssertGreaterThan(allActions.count, 0)
        XCTAssertTrue(allActions.contains(.read))
        XCTAssertTrue(allActions.contains(.download))
    }

    // MARK: - Generic Configuration Tests

    func testGenericRARConfiguration() {
        let registry = CustomRARTypeRegistry()
        let config = GenericRARConfiguration<CustomRARTypeRegistry>(
            allowCustomTypes: true,
            maxAuthorizationDetails: 3,
            validateURIs: false,
            allowedTypes: [.documentAccess, .userProfile],
            allowedActions: [.read, .download],
            typeRegistry: registry
        )

        XCTAssertTrue(config.allowCustomTypes)
        XCTAssertEqual(config.maxAuthorizationDetails, 3)
        XCTAssertFalse(config.validateURIs)
        XCTAssertEqual(config.allowedTypes?.count, 2)
        XCTAssertEqual(config.allowedActions?.count, 2)
    }

    // MARK: - Type System Features Tests

    func testSwiftTypeSystemExample() {
        let registry = CustomRARTypeRegistry()

        // Test generic function
        let result1 = SwiftTypeSystemExample.processWithAnyRegistry(
            registry: registry,
            type: "document_access"
        )
        XCTAssertTrue(result1.contains("is registered"))

        let result2 = SwiftTypeSystemExample.processWithAnyRegistry(
            registry: registry,
            type: "nonexistent_type"
        )
        XCTAssertTrue(result2.contains("is not registered"))

        // Test strict configuration
        let strictConfig = SwiftTypeSystemExample.createStrictConfiguration()
        XCTAssertFalse(strictConfig.allowCustomTypes)
        XCTAssertEqual(strictConfig.maxAuthorizationDetails, 5)
        XCTAssertEqual(strictConfig.allowedTypes?.count, 2)
        XCTAssertEqual(strictConfig.allowedActions?.count, 2)

        // Test type-safe authorization detail creation
        let authDetail = SwiftTypeSystemExample.createTypeSafeAuthorizationDetail()
        XCTAssertEqual(authDetail.type, "document_access")
        XCTAssertEqual(authDetail.actions, ["read", "download"])
        XCTAssertEqual(authDetail.locations, ["https://api.example.com/documents"])
    }

    // MARK: - Protocol Conformance Tests

    func testProtocolConformance() {
        // Test that our types conform to the required protocols
        let types: [any RARTypeProtocol] = [RARType.paymentInitiation, CustomRARType.documentAccess]
        let actions: [any RARActionProtocol] = [RARAction.read, CustomRARAction.download]

        XCTAssertEqual(types.count, 2)
        XCTAssertEqual(actions.count, 2)

        // Test that they can be used in sets (Hashable conformance)
        let typeSet: Set<RARType> = [.paymentInitiation, .accountAccess]
        let actionSet: Set<RARAction> = [.read, .write]

        XCTAssertEqual(typeSet.count, 2)
        XCTAssertEqual(actionSet.count, 2)
    }

    // MARK: - CaseIterable Tests

    func testCaseIterableConformance() {
        // Test that our enums conform to CaseIterable
        let allRARTypes = RARType.allCases
        XCTAssertGreaterThan(allRARTypes.count, 0)
        XCTAssertTrue(allRARTypes.contains(.paymentInitiation))
        XCTAssertTrue(allRARTypes.contains(.accountAccess))

        let allRARActions = RARAction.allCases
        XCTAssertGreaterThan(allRARActions.count, 0)
        XCTAssertTrue(allRARActions.contains(.read))
        XCTAssertTrue(allRARActions.contains(.write))

        let allCustomTypes = CustomRARType.allCases
        XCTAssertEqual(allCustomTypes.count, 4)
        XCTAssertTrue(allCustomTypes.contains(.documentAccess))
        XCTAssertTrue(allCustomTypes.contains(.userProfile))

        let allCustomActions = CustomRARAction.allCases
        XCTAssertGreaterThan(allCustomActions.count, 0)
        XCTAssertTrue(allCustomActions.contains(.read))
        XCTAssertTrue(allCustomActions.contains(.download))
    }
}
