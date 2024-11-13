package com.michaelgerullis.cordovadeviceauthenticity;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import android.os.Build;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.PackageInfo;
import android.util.Base64;
import android.util.Log;

public class CordovaDeviceAuthenticity extends CordovaPlugin {

    private static final String TAG = "CordovaDeviceAuthenticity";
    private static final String DEFAULT_ALLOWED_STORE = "com.android.vending";
    private static final String[] DEFAULT_FORBIDDEN_TAGS = new String[] {
            "test-keys", "dev-keys", "userdebug", "engineering", "release-keys-debug",
            "custom", "rooted", "supersu", "magisk", "lineage", "unofficial"
    };

    private static final String[] DEFAULT_FORBIDDEN_PATHS = new String[] {
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"
    };

    private static final String[] DEFAULT_FORBIDDEN_EXECUTABLES = new String[] {
            "su", "/system/xbin/su", "/system/bin/su", "busybox"
    };

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        Log.d(TAG, "Action: " + action + ", Args: " + args.toString());
        if (action.equals("checkAuthenticity")) {
            this.checkAuthenticity(args, callbackContext);
            return true;
        } else if (action.equals("isRooted")) {
            this.isRooted(args, callbackContext);
            return true;
        } else if (action.equals("isEmulator")) {
            this.isEmulator(callbackContext);
            return true;
        } else if (action.equals("isNotInstalledFromAllowedStore")) {
            this.isNotInstalledFromAllowedStore(args, callbackContext);
            return true;
        } else if (action.equals("getApkCertSignature")) {
            this.getApkCertSignature(callbackContext);
            return true;
        } else if (action.equals("checkApkCertSignature")) {
            this.checkApkCertSignature(args, callbackContext);
            return true;
        } else if (action.equals("checkTags")) {
            this.checkTags(args, callbackContext);
            return true;
        } else if (action.equals("checkPaths")) {
            callbackContext.success("checkPaths called");
            // this.checkPaths(args, callbackContext);
            return true;
        } else if (action.equals("checkExecutableFiles")) {
            this.checkExecutableFiles(args, callbackContext);
            return true;
        }
        return false;
    }

    private void checkAuthenticity(JSONArray args, CallbackContext callbackContext) {
        try {
            JSONObject params = args.getJSONObject(0);
            String expectedApkSignature = params.optString("expectedApkSignature");
            JSONArray rootIndicatorTags = params.optJSONArray("rootIndicatorTags");
            JSONArray rootIndicatorPaths = params.optJSONArray("rootIndicatorPaths");
            JSONArray rootIndicatorFiles = params.optJSONArray("rootIndicatorFiles");
            JSONArray allowedStores = params.optJSONArray("allowedStores");

            JSONObject result = new JSONObject();
            JSONArray failedChecks = new JSONArray();
            String apkSignature = _getApkCertSignature();

            boolean isRooted = _checkIsRooted(rootIndicatorTags, rootIndicatorPaths, rootIndicatorFiles);
            boolean isEmulator = _isEmulator() || _isRunningInEmulator();
            boolean hasOffendingPaths = _checkPaths(rootIndicatorPaths);
            boolean hasOffendingTags = _checkTags(rootIndicatorTags);
            boolean hasOffendingExecutableFiles = _checkExecutableFiles(rootIndicatorFiles);
            boolean isNotInstalledFromAllowedStore = _isNotInstalledFromAllowedStore(_getAllowedStores(allowedStores));
            
            result.put("isRooted", isRooted);
            result.put("isEmulator", isEmulator);
            result.put("hasOffendingPaths", hasOffendingPaths);
            result.put("hasOffendingTags", hasOffendingTags);
            result.put("hasOffendingExecutableFiles", hasOffendingExecutableFiles);
            result.put("isNotInstalledFromAllowedStore", isNotInstalledFromAllowedStore);

            if (isRooted) failedChecks.put("isRooted");
            if (isEmulator) failedChecks.put("isEmulator");
            if (hasOffendingPaths) failedChecks.put("hasOffendingPaths");
            if (hasOffendingTags) failedChecks.put("hasOffendingTags");
            if (hasOffendingExecutableFiles) failedChecks.put("hasOffendingExecutableFiles");
            if (isNotInstalledFromAllowedStore) failedChecks.put("isNotInstalledFromAllowedStore");

            if (expectedApkSignature != null && !expectedApkSignature.isEmpty()) {
                Boolean signatureMatch = _checkApkCertSignature(expectedApkSignature);
                result.put("apkCertSignatureMatch", signatureMatch);
                if (!signatureMatch) failedChecks.put("apkCertSignatureMatch");
            }
            if (apkSignature != null && !apkSignature.isEmpty()) {
                result.put("apkCertSignature", apkSignature);
            }

            result.put("failedChecks", failedChecks);
            callbackContext.success(result);
        } catch (Exception e) {
            Log.e(TAG, "Error in checkAuthenticity: " + e.getMessage(), e);
            callbackContext.error("Error checking device authenticity: " + e.getMessage());
        }
    }

    private void isRooted(JSONArray args, CallbackContext callbackContext) {
        try {
            JSONObject params = args.optJSONObject(0);
            JSONArray rootIndicatorTags = params != null ? params.optJSONArray("rootIndicatorTags") : null;
            JSONArray rootIndicatorPaths = params != null ? params.optJSONArray("rootIndicatorPaths") : null;
            JSONArray rootIndicatorFiles = params != null ? params.optJSONArray("rootIndicatorFiles") : null;
            boolean isRooted = _checkIsRooted(rootIndicatorTags, rootIndicatorPaths, rootIndicatorFiles);
            JSONObject result = new JSONObject();
            result.put("isRooted", isRooted);
            callbackContext.success(result);
        } catch (Exception e) {
            Log.e(TAG, "Error in isRooted: " + e.getMessage(), e);
            callbackContext.error("Error checking device rooted status: " + e.getMessage());
        }
    }


    private void isEmulator(CallbackContext callbackContext) {
        try {
            JSONObject result = new JSONObject();
            result.put("isEmulator", _isEmulator() || _isRunningInEmulator());
            callbackContext.success("");
        } catch (Exception e) {
            callbackContext.error("Error checking device emulator status: " + e.getMessage());
        }
    }

    private void isNotInstalledFromAllowedStore(JSONArray args, CallbackContext callbackContext) {
        try {
            JSONObject params = args.optJSONObject(0);
            JSONArray allowedStores = params != null ? params.optJSONArray("allowedStores") : null;
            JSONObject result = new JSONObject();
            result.put("isNotInstalledFromAllowedStore", _isNotInstalledFromAllowedStore(_getAllowedStores(allowedStores)));
            callbackContext.success(result);
        } catch (Exception e) {
            callbackContext.error("Error checking installation source: " + e.getMessage());
        }
    }

    private void getApkCertSignature(CallbackContext callbackContext) {
        try {
            JSONObject result = new JSONObject();
            result.put("apkCertSignature", _getApkCertSignature());
            callbackContext.success(result);
        } catch (Exception e) {
            callbackContext.error("Error getting APK certificate signature: " + e.getMessage());
        }
    }

    private void checkApkCertSignature(JSONArray args, CallbackContext callbackContext) {
        try {
            JSONObject params = args.optJSONObject(0);
            String expectedApkSignature = params != null ? params.optString("expectedApkSignature") : null;
            JSONObject result = new JSONObject();
            
            if (expectedApkSignature == null || expectedApkSignature.isEmpty()) {
                callbackContext.error("No APK signature provided. Args: " + args.toString() + ", Params: " + (params != null ? params.toString() : "null"));
                return;
            }

            String actualSignature = _getApkCertSignature();
            boolean matches = expectedApkSignature.equals(actualSignature);
            result.put("apkCertSignatureMatches", matches);
            
            callbackContext.success(result);
        } catch (Exception e) {
            callbackContext.error("Error checking APK certificate signature: " + e.getMessage());
        }
    }

    private void checkTags(JSONArray args, CallbackContext callbackContext) {
        try {
            JSONObject params = args.optJSONObject(0);
            JSONArray rootIndicatorTags = params != null ? params.optJSONArray("rootIndicatorTags") : null;
            JSONObject result = new JSONObject();
            result.put("hasOffendingTags", _checkTags(rootIndicatorTags));
            callbackContext.success(result);
        } catch (Exception e) {
            Log.e(TAG, "Error in checkTags: " + e.getMessage(), e);
            callbackContext.error("Error checking build tags: " + e.getMessage());
        }
    }

    private void checkPaths(JSONArray args, CallbackContext callbackContext) {
        try {
            JSONObject params = args.optJSONObject(0);
            JSONArray rootIndicatorPaths = params != null ? params.optJSONArray("rootIndicatorPaths") : null;
            JSONObject result = new JSONObject();
            result.put("hasOffendingPaths", _checkPaths(rootIndicatorPaths));
            callbackContext.success(result);
        } catch (Exception e) {
            Log.e(TAG, "Error in checkPaths: " + e.getMessage(), e);
            callbackContext.error("Error checking build paths: " + e.getMessage());
        }
    }

    private void checkExecutableFiles(JSONArray args, CallbackContext callbackContext) {
        try {
            JSONObject params = args.optJSONObject(0);
            JSONArray rootIndicatorFiles = params != null ? params.optJSONArray("rootIndicatorFiles") : null;
            JSONObject result = new JSONObject();
            result.put("hasOffendingExecutableFiles", _checkExecutableFiles(rootIndicatorFiles));
            callbackContext.success(result);
        } catch (Exception e) {
            Log.e(TAG, "Error in checkExecutableFiles: " + e.getMessage(), e);
            callbackContext.error("Error checking executable files: " + e.getMessage());
        }
    }

    private String _getApkCertSignature() throws PackageManager.NameNotFoundException, NoSuchAlgorithmException {
        PackageInfo packageInfo;
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo = cordova.getActivity().getPackageManager().getPackageInfo(cordova.getActivity().getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES);
            Signature[] signatures = packageInfo.signingInfo.getApkContentsSigners();
            return _calculateSignature(signatures[0]);
        } else {
            packageInfo = cordova.getActivity().getPackageManager().getPackageInfo(cordova.getActivity().getPackageName(),
                    PackageManager.GET_SIGNATURES);
            Signature[] signatures = packageInfo.signatures;
            return _calculateSignature(signatures[0]);
        }
    }

    private Boolean _checkApkCertSignature(String expectedApkSignature) {
        try {
            String apkSignature = _getApkCertSignature();
            if (expectedApkSignature == null || expectedApkSignature.isEmpty()) {
                return true;
            }
            String parsedExpectedApkSignature = expectedApkSignature.replace(":", "").toLowerCase();
            String parsedApkSignature = apkSignature.replace(":", "").toLowerCase();
            boolean isValid = parsedApkSignature.equals(parsedExpectedApkSignature);
            return isValid;
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // Returns a lowercase hex string without colons of the SHA-256 hash of the signature
    // todo: make it so we can specify the format (hex, base64, etc.)
    private String _calculateSignature(Signature sig) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(sig.toByteArray());
        byte[] digest = md.digest();
        
        // Convert to colon-separated hex format
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            String hex = String.format("%02X", b);
            if (hexString.length() > 0) {
                hexString.append(":");
            }
            hexString.append(hex);
        }
        return hexString.toString().replace(":", "").toLowerCase();
    }

    private boolean _isEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk".equals(Build.PRODUCT);
    }

    private boolean _isRunningInEmulator() {
        boolean result = false;
        try {
            String buildDetails = Build.FINGERPRINT + Build.DEVICE + Build.MODEL + Build.BRAND + Build.PRODUCT
                    + Build.MANUFACTURER + Build.HARDWARE;
            result = buildDetails.toLowerCase().contains("generic")
                    || buildDetails.toLowerCase().contains("emulator")
                    || buildDetails.toLowerCase().contains("sdk");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private boolean _checkIsRooted(JSONArray rootIndicatorTagsArray, JSONArray rootIndicatorPathsArray,
            JSONArray rootIndicatorFilesArray) {

        try {
            return _checkTags(rootIndicatorTagsArray)
                    || _checkPaths(rootIndicatorPathsArray)
                    || _checkExecutableFiles(rootIndicatorFilesArray);
        } catch (JSONException e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean _checkTags(JSONArray rootIndicatorTagsArray) throws JSONException {
        String buildTags = android.os.Build.TAGS;
        String[] tagsToCheck;

        if (buildTags == null || buildTags.isEmpty())
            return false;

        if (rootIndicatorTagsArray != null && rootIndicatorTagsArray.length() > 0) {
            tagsToCheck = new String[rootIndicatorTagsArray.length()];
            for (int i = 0; i < rootIndicatorTagsArray.length(); i++) {
                tagsToCheck[i] = rootIndicatorTagsArray.getString(i);
            }
        } else {
            tagsToCheck = DEFAULT_FORBIDDEN_TAGS;
        }

        for (String tag : tagsToCheck) {
            if (buildTags.toLowerCase().contains(tag.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    private boolean _checkPaths(JSONArray rootIndicatorPathsArray) throws JSONException {
        String[] paths;

        if (rootIndicatorPathsArray != null && rootIndicatorPathsArray.length() > 0) {
            paths = new String[rootIndicatorPathsArray.length()];
            for (int i = 0; i < rootIndicatorPathsArray.length(); i++) {
                paths[i] = rootIndicatorPathsArray.getString(i);
            }
        } else {
            paths = DEFAULT_FORBIDDEN_PATHS;
        }
        for (String path : paths) {
            if (new File(path).exists())
                return true;
        }
        return false;
    }

    private boolean _checkExecutableFiles(JSONArray rootIndicatorFilesArray) throws JSONException {
        ArrayList<String> executableFiles;

        if (rootIndicatorFilesArray != null && rootIndicatorFilesArray.length() > 0) {
            executableFiles = new ArrayList<>();
            for (int i = 0; i < rootIndicatorFilesArray.length(); i++) {
                executableFiles.add(rootIndicatorFilesArray.getString(i));
            }
        } else {
            executableFiles = new ArrayList<>(Arrays.asList(DEFAULT_FORBIDDEN_EXECUTABLES));
        }

        ArrayList<String> commands = new ArrayList<>(Arrays.asList(
                "which",
                "id",
                "ls /data"));

        for (String executableFile : executableFiles) {
            for (String command : commands) {
                String fullCommand = executableFile + " -c " + command;
                if (_executeCommand(fullCommand)) {
                    return true;
                }
            }
            if (_executeCommand(executableFile)) {
                return true;
            }
        }
        return false;
    }

    private boolean _executeCommand(String command) {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            reader.close();
            return line != null;
        } catch (IOException e) {
            return false;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private boolean _isNotInstalledFromAllowedStore(List<String> allowedStores) {
        try {
            String installer = cordova.getActivity().getPackageManager()
                    .getInstallerPackageName(cordova.getActivity().getPackageName());
            if (installer == null) {
                return false;
            }
            if (allowedStores == null || allowedStores.isEmpty()) {
                return true;
            }
            for (String store : allowedStores) {
                if (installer.equals(store)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private List<String> _getAllowedStores(JSONArray allowedStoresArray) throws JSONException {
        List<String> allowedStores = new ArrayList<>();

        if (allowedStoresArray != null && allowedStoresArray.length() > 0) {
            for (int i = 0; i < allowedStoresArray.length(); i++) {
                allowedStores.add(allowedStoresArray.getString(i));
            }
        } else {
            allowedStores.add(DEFAULT_ALLOWED_STORE);
        }
        return allowedStores;
    }
}