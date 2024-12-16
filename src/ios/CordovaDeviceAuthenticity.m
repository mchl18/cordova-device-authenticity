#import "CordovaDeviceAuthenticity.h"
#import <UIKit/UIKit.h>

@implementation CordovaDeviceAuthenticity

- (void)checkAuthenticity:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        NSDictionary* options = [command.arguments objectAtIndex:0];
        NSArray* jailbreakIndicatorPaths = options[@"jailbreakIndicatorPaths"] ?: @[];
        NSArray* forbiddenAppStoreSchemas = options[@"forbiddenAppStoreSchemas"] ?: @[];
        
        BOOL isEmulator = [self isRunningOnSimulator];
        NSDictionary* pathsCheck = [self checkOffendingPaths:jailbreakIndicatorPaths];
        NSDictionary* privateWriteCheck = [self checkPrivateWrite];
        NSDictionary* thirdPartyStoreCheck = [self checkThirdPartyAppStore:forbiddenAppStoreSchemas];
        
        BOOL isJailbroken = isEmulator || 
            [privateWriteCheck[@"canWritePrivate"] boolValue] || 
            [pathsCheck[@"hasOffendingPaths"] boolValue] || 
            [thirdPartyStoreCheck[@"hasThirdPartyAppStore"] boolValue];
        
        NSMutableArray* failedChecks = [NSMutableArray array];
        if (isJailbroken) [failedChecks addObject:@"isJailbroken"];
        if (isEmulator) [failedChecks addObject:@"isEmulator"];
        if ([privateWriteCheck[@"canWritePrivate"] boolValue]) [failedChecks addObject:@"canWritePrivate"];
        if ([pathsCheck[@"hasOffendingPaths"] boolValue]) [failedChecks addObject:@"hasOffendingPaths"];
        if ([thirdPartyStoreCheck[@"hasThirdPartyAppStore"] boolValue]) [failedChecks addObject:@"hasThirdPartyAppStore"];
        
        NSDictionary* result = @{
            @"isJailbroken": @(isJailbroken),
            @"isEmulator": @(isEmulator),
            @"hasThirdPartyAppStore": thirdPartyStoreCheck[@"hasThirdPartyAppStore"],
            @"detectedThirdPartyAppStoreSchemas": thirdPartyStoreCheck[@"detectedSchemas"],
            @"canWritePrivate": privateWriteCheck[@"canWritePrivate"],
            @"detectedPrivateWritePaths": privateWriteCheck[@"detectedPaths"],
            @"hasOffendingPaths": pathsCheck[@"hasOffendingPaths"],
            @"detectedForbiddenPaths": pathsCheck[@"detectedPaths"],
            @"failedChecks": failedChecks
        };
        
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)isEmulator:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        BOOL isEmulator = [self isRunningOnSimulator];
        NSDictionary* result = @{@"isEmulator": @(isEmulator)};
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)isJailbroken:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        NSDictionary* options = [command.arguments objectAtIndex:0];
        NSArray* jailbreakIndicatorPaths = options[@"jailbreakIndicatorPaths"] ?: @[];
        NSArray* forbiddenAppStoreSchemas = options[@"forbiddenAppStoreSchemas"] ?: @[];
        
        NSDictionary* pathsCheck = [self checkOffendingPaths:jailbreakIndicatorPaths];
        NSDictionary* privateWriteCheck = [self checkPrivateWrite];
        NSDictionary* thirdPartyStoreCheck = [self checkThirdPartyAppStore:forbiddenAppStoreSchemas];
        
        BOOL isJailbroken = [pathsCheck[@"hasOffendingPaths"] boolValue] || 
            [privateWriteCheck[@"canWritePrivate"] boolValue] || 
            [thirdPartyStoreCheck[@"hasThirdPartyAppStore"] boolValue];
        
        NSDictionary* result = @{
            @"isJailbroken": @(isJailbroken),
            @"detectedForbiddenPaths": pathsCheck[@"detectedPaths"],
            @"canWritePrivate": privateWriteCheck[@"canWritePrivate"],
            @"detectedPrivateWritePaths": privateWriteCheck[@"detectedPaths"],
            @"detectedThirdPartyAppStoreSchemas": thirdPartyStoreCheck[@"detectedSchemas"]
        };
        
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (NSDictionary*)checkOffendingPaths:(NSArray*)customPaths {
    NSArray* defaultPaths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Applications/Zebra.app",
        @"/Applications/Installer.app",
        @"/Applications/Unc0ver.app",
        @"/Applications/Checkra1n.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/usr/sbin/sshd",
        @"/usr/bin/sshd",
        @"/usr/libexec/sftp-server",
        @"/etc/apt",
        @"/private/var/lib/apt/",
        @"/private/var/mobile/Library/Cydia/",
        @"/private/var/stash",
        @"/private/var/db/stash",
        @"/private/var/jailbreak",
        @"/var/mobile/Library/SBSettings/Themes"
    ];
    
    NSArray* pathsToCheck = customPaths.count > 0 ? customPaths : defaultPaths;
    NSMutableArray* detectedPaths = [NSMutableArray array];
    
    for (NSString* path in pathsToCheck) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            [detectedPaths addObject:path];
        }
    }
    
    return @{
        @"hasOffendingPaths": @(detectedPaths.count > 0),
        @"detectedPaths": detectedPaths
    };
}

- (NSDictionary*)checkPrivateWrite {
    NSString* testPath = @"/private/jailbreak.txt";
    NSError* error;
    
    [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    
    if (!error) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return @{
            @"canWritePrivate": @YES,
            @"detectedPaths": @[@"/private"]
        };
    }
    
    return @{
        @"canWritePrivate": @NO,
        @"detectedPaths": @[]
    };
}

- (NSDictionary*)checkThirdPartyAppStore:(NSArray*)customSchemas {
    NSArray* defaultSchemas = @[
        @"cydia://",
        @"sileo://",
        @"zbra://",
        @"filza://",
        @"undecimus://",
        @"activator://"
    ];
    
    NSArray* schemasToCheck = customSchemas.count > 0 ? customSchemas : defaultSchemas;
    NSMutableArray* detectedSchemas = [NSMutableArray array];
    
    for (NSString* schema in schemasToCheck) {
        NSURL* url = [NSURL URLWithString:schema];
        if ([[UIApplication sharedApplication] canOpenURL:url]) {
            [detectedSchemas addObject:schema];
        }
    }
    
    return @{
        @"hasThirdPartyAppStore": @(detectedSchemas.count > 0),
        @"detectedSchemas": detectedSchemas
    };
}

- (BOOL)isRunningOnSimulator {
    #if TARGET_IPHONE_SIMULATOR
        return YES;
    #else
        return NO;
    #endif
}

// Unimplemented methods that return error
- (void)isRooted:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Not implemented on iOS"];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)isInstalledFromAllowedStore:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Not implemented on iOS"];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getApkCertSignature:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Not implemented on iOS"];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)checkApkCertSignature:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Not implemented on iOS"];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)checkTags:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Not implemented on iOS"];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end 