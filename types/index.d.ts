interface DeviceAuthenticityOptions {
  expectedApkSignature?: string;
  rootIndicatorTags?: string[];
  rootIndicatorPaths?: string[];
  rootIndicatorFiles?: string[];
  allowedStores?: string[];
}

interface DeviceAuthenticityResult {
  isJailbroken: boolean;
  isEmulator: boolean;
  hasThirdPartyAppStore?: boolean;
  detectedThirdPartyAppStoreSchemas?: string[];
  canWritePrivate?: boolean;
  detectedPrivateWritePaths?: string[];
  hasOffendingPaths: boolean;
  detectedForbiddenPaths?: string[];
  apkCertSignature?: string;
  apkCertSignatureMatch?: boolean;
  hasOffendingTags: boolean;
  hasOffendingExecutableFiles: boolean;
  failedChecks?: string[];
}

interface SignatureResult {
  algorithm: string;
  toString: string;
  toCharsString: string;
  base64: string;
  androidVersion: number;
  signatureMethod: string;
}

declare module "cordova-device-authenticity" {
  export function checkAuthenticity(
    options?: DeviceAuthenticityOptions
  ): Promise<DeviceAuthenticityResult>;
  export function isRooted(
    options?: DeviceAuthenticityOptions
  ): Promise<{ isRooted: boolean }>;
  export function isEmulator(): Promise<{ isEmulator: boolean }>;
  export function getApkCertSignature(): Promise<SignatureResult>;
  export function checkApkCertSignature(options: {
    expectedApkSignature: string;
  }): Promise<{ apkCertSignatureMatches: boolean }>;
  export function checkTags(options?: {
    rootIndicatorTags?: string[];
  }): Promise<{ hasOffendingTags: boolean }>;
  export function checkPaths(options?: {
    rootIndicatorPaths?: string[];
  }): Promise<{ hasOffendingPaths: boolean }>;
  export function checkExecutableFiles(options?: {
    rootIndicatorFiles?: string[];
  }): Promise<{ hasOffendingExecutableFiles: boolean }>;
}
