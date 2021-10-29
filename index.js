const https = require('https');
const formatter = require('./lib/formatter');

const DSTRootCAX3 = 
"-----BEGIN CERTIFICATE-----\n" +
"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/MSQwIgYDVQQK\n" +
"ExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4X\n" +
"DTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVowPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1\n" +
"cmUgVHJ1c3QgQ28uMRcwFQYDVQQDEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
"ggEPADCCAQoCggEBAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmT\n" +
"rE4Orz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEqOLl5CjH9\n" +
"UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9bxiqKqy69cK3FCxolkHRy\n" +
"xXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40d\n" +
"utolucbY38EVAjqr2m7xPi71XAicPNaDaeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0T\n" +
"AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQ\n" +
"MA0GCSqGSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69ikug\n" +
"dB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXrAvHRAosZy5Q6XkjE\n" +
"GB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZzR8srzJmwN0jP41ZL9c8PDHIyh8bw\n" +
"RLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubS\n" +
"fZGL+T0yjWW06XyxV3bqxbYoOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n" +
"-----END CERTIFICATE-----\n";

if (process.platform !== 'darwin') {
  module.exports.all = () => [];
  module.exports.each = () => {};
}
else {
  const child_process = require('child_process');

  const splitPattern = /(?=-----BEGIN\sCERTIFICATE-----)/g;
  const systemRootCertsPath = '/System/Library/Keychains/SystemRootCertificates.keychain';
  const args = [ 'find-certificate', '-a', '-p' ];

  const allTrusted = child_process.spawnSync('/usr/bin/security', args)
    .stdout.toString().split(splitPattern);

  const allRoot = child_process.spawnSync('/usr/bin/security', args.concat(systemRootCertsPath))
    .stdout.toString().split(splitPattern);

  https.globalAgent.options.ca = https.globalAgent.options.ca || [];

  const ca = https.globalAgent.options.ca;

  function duplicated(cert, index, arr) {
    return arr.indexOf(cert) === index;
  }

  const all = allTrusted.concat(allRoot);

  const noDuplicated = all.filter(duplicated);
  const noExpired = noDuplicated.filter(cert => !cert.includes(DSTRootCAX3));

  if (noExpired.length < noDuplicated) {
    console.log('[MAC-CA]: Filtered expired CA');
  }

  noExpired.forEach(cert => ca.push(cert));

  module.exports.der2 = formatter.validFormats;

  module.exports.all = function(format){
    return all
      .map(formatter.transform(format))
      .filter(c => c);
  };

  module.exports.each = function(format, callback) {
    if (typeof format === 'function') {
      callback = format;
      format = undefined;
    }
    return all
      .map(formatter.transform(format))
      .filter(c => c)
      .forEach(callback);
  };
}
