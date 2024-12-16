#import <Cordova/CDVPlugin.h>

@interface CordovaDeviceAuthenticity : CDVPlugin

- (void)checkAuthenticity:(CDVInvokedUrlCommand*)command;
- (void)isEmulator:(CDVInvokedUrlCommand*)command;
- (void)isJailbroken:(CDVInvokedUrlCommand*)command;
- (void)checkPaths:(CDVInvokedUrlCommand*)command;
- (void)checkPrivateWrite:(CDVInvokedUrlCommand*)command;
- (void)hasThirdPartyAppStore:(CDVInvokedUrlCommand*)command;
- (void)isRooted:(CDVInvokedUrlCommand*)command;
- (void)isInstalledFromAllowedStore:(CDVInvokedUrlCommand*)command;
- (void)getApkCertSignature:(CDVInvokedUrlCommand*)command;
- (void)checkApkCertSignature:(CDVInvokedUrlCommand*)command;
- (void)checkTags:(CDVInvokedUrlCommand*)command;

@end 