var deviceAuthenticity = {
  checkAuthenticity: function (options = {}) {
    return new Promise(function (resolve, reject) {
      cordova.exec(
        resolve,
        reject,
        "CordovaDeviceAuthenticity",
        "checkAuthenticity",
        [options]
      );
    });
  },

  isRooted: function (options = {}) {
    return new Promise(function (resolve, reject) {
      cordova.exec(resolve, reject, "CordovaDeviceAuthenticity", "isRooted", [
        options,
      ]);
    });
  },

  isEmulator: function () {
    return new Promise(function (resolve, reject) {
      cordova.exec(
        resolve,
        reject,
        "CordovaDeviceAuthenticity",
        "isEmulator",
        []
      );
    });
  },
  /**
   *
   * @param {object} options
   * @param {string[]} options.rootIndicatorFiles
   * @returns {{isNotInstalledFromAllowedStore: boolean}}
   */
  isNotInstalledFromAllowedStore: function (options = {}) {
    return new Promise(function (resolve, reject) {
      cordova.exec(
        resolve,
        reject,
        "CordovaDeviceAuthenticity",
        "isInstalledFromAllowedStore",
        [options]
      );
    });
  },

  /**
   *
   * @returns {{apkCertSignature: string}}
   */
  getApkCertSignature: function () {
    return new Promise(function (resolve, reject) {
      cordova.exec(
        resolve,
        reject,
        "CordovaDeviceAuthenticity",
        "getApkCertSignature",
        []
      );
    });
  },

  /**
   *
   * @param {object} options
   * @param {string} options.apkCertSignature
   * @returns {{apkCertSignatureMatches: boolean}}
   */
  checkApkCertSignature: function (options = {}) {
    return new Promise(function (resolve, reject) {
      if (!options.apkCertSignature) {
        return reject(
          "No options provided, please provide an APK certificate signature"
        );
      }
      cordova.exec(
        resolve,
        reject,
        "CordovaDeviceAuthenticity",
        "checkApkCertSignature",
        [options]
      );
    });
  },

  /**
   *
   * @param {object} options
   * @param {string[]} options.rootIndicatorTags
   * @returns {{hasOffendingTags: boolean}}
   */
  checkTags: function (options = {}) {
    return new Promise(function (resolve, reject) {
      cordova.exec(resolve, reject, "CordovaDeviceAuthenticity", "checkTags", [
        options,
      ]);
    });
  },

  /**
   *
   * @param {object} options
   * @param {string[]} options.rootIndicatorPaths
   * @returns {{hasOffendingPaths: boolean}}
   */
  checkPaths: function (options = {}) {
    return new Promise(function (resolve, reject) {
      cordova.exec(resolve, reject, "CordovaDeviceAuthenticity", "checkPaths", [
        options,
      ]);
    });
  },

  /**
   *
   * @param {object} options
   * @param {string[]} options.rootIndicatorFiles
   * @returns {{hasOffendingExecutableFiles: boolean}}
   */
  checkExecutableFiles: function (options = {}) {
    return new Promise(function (resolve, reject) {
      cordova.exec(
        resolve,
        reject,
        "CordovaDeviceAuthenticity",
        "checkExecutableFiles",
        [options]
      );
    });
  },
};

module.exports = deviceAuthenticity;
