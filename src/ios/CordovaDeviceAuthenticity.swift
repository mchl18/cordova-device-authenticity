import Foundation
import Cordova

@objc(CordovaDeviceAuthenticity) class CordovaDeviceAuthenticity : CDVPlugin {
    struct CheckPathsResult {
        let hasOffendingPaths: Bool
        let detectedForbiddenPaths: [String]
    }
    struct CheckAppstoresResult {
        let hasThirdPartyAppStore: Bool
        let forbiddenAppStoreSchemas: [String]
    }
    struct CheckPrivateWriteResult {
        let canWritePrivate: Bool
        let detectedPrivateWritePaths: [String]
    }

    struct CheckJailbreakResult {
        let isJailbroken: Bool
        let canWritePrivate: Bool
        let hasOffendingPaths: Bool
        let detectedForbiddenPaths: [String]
        let forbiddenAppStoreSchemas: [String]
        let detectedPrivateWritePaths: [String]
    }

    @objc(checkAuthenticity:)
    func checkAuthenticity(command: CDVInvokedUrlCommand) {
        let options = command.arguments[0] as? [String: Any] ?? [:]
        let jailbreakIndicatorPaths = options["jailbreakIndicatorPaths"] as? [String] ?? []
        let forbiddenAppStoreSchemas = options["forbiddenAppStoreSchemas"] as? [String] ?? []
        
        // Get all check results
        let hasPaths = _checkOffendingPaths(jailbreakIndicatorPaths: jailbreakIndicatorPaths)
        let canWritePrivate = _checkPrivateWrite()
        let isEmulator = _isRunningOnSimulator()
        let hasThirdPartyAppStore = _hasThirdPartyAppStore(forbiddenAppStoreSchemas: forbiddenAppStoreSchemas)
        
        // Calculate isJailbroken based on all checks
        let isJailbroken = isEmulator || 
            canWritePrivate.canWritePrivate || 
            hasPaths.hasOffendingPaths || 
            hasThirdPartyAppStore.hasThirdPartyAppStore
        
        // Build failedChecks array
        var failedChecks: [String] = []
        
        // Add each failed check to the array
        if isJailbroken {
            failedChecks.append("isJailbroken")
        }
        if isEmulator {
            failedChecks.append("isEmulator")
        }
        if canWritePrivate.canWritePrivate {
            failedChecks.append("canWritePrivate")
        }
        if hasPaths.hasOffendingPaths {
            failedChecks.append("hasOffendingPaths")
        }
        if hasThirdPartyAppStore.hasThirdPartyAppStore {
            failedChecks.append("hasThirdPartyAppStore")
        }

        // Build result dictionary with all check results and details
        let result = [
            "isJailbroken": isJailbroken,
            "isEmulator": isEmulator,
            "hasThirdPartyAppStore": hasThirdPartyAppStore.hasThirdPartyAppStore,
            "detectedThirdPartyAppStoreSchemas": hasThirdPartyAppStore.forbiddenAppStoreSchemas,
            "canWritePrivate": canWritePrivate.canWritePrivate,
            "detectedPrivateWritePaths": canWritePrivate.detectedPrivateWritePaths,
            "hasOffendingPaths": hasPaths.hasOffendingPaths,
            "detectedForbiddenPaths": hasPaths.detectedForbiddenPaths,
            "failedChecks": failedChecks
        ] as [String : Any]

        let pluginResult = CDVPluginResult(status: .ok, messageAs: result)
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }
    
    @objc(isEmulator:)
    func isEmulator(command: CDVInvokedUrlCommand) {
        let isEmulator = _isRunningOnSimulator()
        
        let pluginResult = CDVPluginResult(status: .ok, messageAs: ["isEmulator": isEmulator])
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(isJailbroken:)
    func isJailbroken(command: CDVInvokedUrlCommand) {
        let options = command.arguments[0] as? [String: Any] ?? [:]
        let jailbreakIndicatorPaths = options["jailbreakIndicatorPaths"] as? [String] ?? []
        let forbiddenAppStoreSchemas = options["forbiddenAppStoreSchemas"] as? [String] ?? []
        let isJailbroken = _checkIsJailbroken(jailbreakIndicatorPaths: jailbreakIndicatorPaths, forbiddenAppStoreSchemas: forbiddenAppStoreSchemas)
        
        let result = [
            "isJailbroken": isJailbroken.isJailbroken, 
            "detectedForbiddenPaths": isJailbroken.detectedForbiddenPaths, 
            "canWritePrivate": isJailbroken.canWritePrivate,
            "detectedPrivateWritePaths": isJailbroken.detectedPrivateWritePaths,
            "detectedThirdPartyAppStoreSchemas": isJailbroken.forbiddenAppStoreSchemas
        ] as [String : Any]
        
        let pluginResult = CDVPluginResult(status: .ok, messageAs: result)
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(checkPaths:)
    func checkPaths(command: CDVInvokedUrlCommand) {
        let options = command.arguments[0] as? [String: Any] ?? [:]
        let jailbreakIndicatorPaths = options["jailbreakIndicatorPaths"] as? [String] ?? []
        let hasPaths = _checkOffendingPaths(jailbreakIndicatorPaths: jailbreakIndicatorPaths)
        
        let pluginResult = CDVPluginResult(status: .ok, messageAs: ["hasPaths": hasPaths.hasOffendingPaths, "detectedForbiddenPaths": hasPaths.detectedForbiddenPaths])
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }
    
    @objc(checkPrivateWrite:)
    func checkPrivateWrite(command: CDVInvokedUrlCommand) {
        let canWritePrivate = _checkPrivateWrite()
        
        let pluginResult = CDVPluginResult(status: .ok, messageAs: ["canWritePrivate": canWritePrivate.canWritePrivate, "detectedPrivateWritePaths": canWritePrivate.detectedPrivateWritePaths])
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(hasThirdPartyAppStore:)
    func hasThirdPartyAppStore(command: CDVInvokedUrlCommand) {
        let options = command.arguments[0] as? [String: Any] ?? [:]
        let forbiddenAppStoreSchemas = options["forbiddenAppStoreSchemas"] as? [String] ?? []
        let hasThirdPartyAppStore = _hasThirdPartyAppStore(forbiddenAppStoreSchemas: forbiddenAppStoreSchemas)
        
        let pluginResult = CDVPluginResult(status: .ok, messageAs: ["hasThirdPartyAppStore": hasThirdPartyAppStore.hasThirdPartyAppStore, "detectedThirdPartyAppStoreSchemas": hasThirdPartyAppStore.forbiddenAppStoreSchemas])
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(isRooted:)
    func isRooted(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: .error, messageAs: "Not implemented on iOS")
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(isInstalledFromAllowedStore:)
    func isInstalledFromAllowedStore(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: .error, messageAs: "Not implemented on iOS")
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(getApkCertSignature:)
    func getApkCertSignature(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: .error, messageAs: "Not implemented on iOS")
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(checkApkCertSignature:)
    func checkApkCertSignature(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: .error, messageAs: "Not implemented on iOS")
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }

    @objc(checkTags:)
    func checkTags(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: .error, messageAs: "Not implemented on iOS")
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }
    
    private func _checkIsJailbroken(jailbreakIndicatorPaths: [String] = [], forbiddenAppStoreSchemas: [String] = []) -> CheckJailbreakResult {
        let checkPathsResult = _checkOffendingPaths(jailbreakIndicatorPaths: jailbreakIndicatorPaths)
        let hasThirdPartyAppStore = _hasThirdPartyAppStore(forbiddenAppStoreSchemas: forbiddenAppStoreSchemas)
        let canWritePrivate = _checkPrivateWrite()
        let isJailbroken = checkPathsResult.hasOffendingPaths || 
            hasThirdPartyAppStore.hasThirdPartyAppStore || 
            canWritePrivate.canWritePrivate

        return CheckJailbreakResult(isJailbroken: isJailbroken,
            canWritePrivate: canWritePrivate.canWritePrivate,
            hasOffendingPaths: checkPathsResult.hasOffendingPaths,
            detectedForbiddenPaths: checkPathsResult.detectedForbiddenPaths,
            forbiddenAppStoreSchemas: hasThirdPartyAppStore.forbiddenAppStoreSchemas,
            detectedPrivateWritePaths: canWritePrivate.detectedPrivateWritePaths)
    }
    
    private func _checkOffendingPaths(jailbreakIndicatorPaths: [String]) -> CheckPathsResult {
        let fileManager = FileManager.default
        let defaultOffendingPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/Installer.app",
            "/Applications/Unc0ver.app",
            "/Applications/Checkra1n.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/private/var/mobile/Library/Cydia/",
            "/private/var/stash",
            "/private/var/db/stash",
            "/private/var/jailbreak",
            "/var/mobile/Library/SBSettings/Themes"
        ]
        var paths: [String] = []
        let pathsToCheck = jailbreakIndicatorPaths.count > 0 ? jailbreakIndicatorPaths : defaultOffendingPaths

        for path in pathsToCheck {
            if fileManager.fileExists(atPath: path) {
                paths.append(path)
            }
        }
        return CheckPathsResult(hasOffendingPaths: !paths.isEmpty, detectedForbiddenPaths: paths)
    }
    
    private func _checkPrivateWrite() -> CheckPrivateWriteResult {
        let fileManager = FileManager.default
        let testPath = "/private/jailbreak.txt"
        
        do {
            // defer will run when exiting the scope, regardless of whether an error occurred
            defer {
                try? fileManager.removeItem(atPath: testPath)
            }
            
            try "jailbreak test".write(toFile: testPath, atomically: true, encoding: .utf8)
            return CheckPrivateWriteResult(canWritePrivate: true, detectedPrivateWritePaths: ["/private"])
        } catch {
            return CheckPrivateWriteResult(canWritePrivate: false, detectedPrivateWritePaths: [])
        }
    }
    
    private func _hasThirdPartyAppStore(forbiddenAppStoreSchemas: [String] = []) -> CheckAppstoresResult {
        let forbiddenAppStoreSchemasDefault = [
            "cydia://",
            "sileo://",
            "zbra://",
            "filza://",
            "undecimus://",
            "activator://"
        ]
        
        let schemasToCheck = forbiddenAppStoreSchemas.count > 0 ? forbiddenAppStoreSchemas : forbiddenAppStoreSchemasDefault
        var foundSchemas: [String] = []
        
        for schema in schemasToCheck {
            if let url = URL(string: schema) {
                if UIApplication.shared.canOpenURL(url) {
                    foundSchemas.append(schema)
                }
            }
        }
        return CheckAppstoresResult(hasThirdPartyAppStore: !foundSchemas.isEmpty, forbiddenAppStoreSchemas: foundSchemas)
    }

    private func _isRunningOnSimulator() -> Bool {
        #if arch(i386) || arch(x86_64)
            return true
        #elseif targetEnvironment(simulator)
            return true
        #else
            return false
        #endif
    }
}