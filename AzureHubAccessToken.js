function hexToBase64UrlEncoded(hexString) {
  // Convert hex to byte array
  var bytes = [];
  for (var i = 0; i < hexString.length; i += 2) {
    bytes.push(parseInt(hexString.substr(i, 2), 16));
  }

  // Base64 character set
  var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var base64 = '';
  var padding = '=';

  // Process every 3 bytes into 4 base64 characters
  for (var i = 0; i < bytes.length; i += 3) {
    var byte1 = bytes[i];
    var byte2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    var byte3 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

    base64 += base64Chars[(triplet >> 18) & 0x3F];
    base64 += base64Chars[(triplet >> 12) & 0x3F];
    base64 += i + 1 < bytes.length ? base64Chars[(triplet >> 6) & 0x3F] : '=';
    base64 += i + 2 < bytes.length ? base64Chars[triplet & 0x3F] : '=';
  }

  // URL-encode the Base64 string
  return encodeURIComponent(base64);
}

function GetAzureHubAccessTokenOIC(uri, saName, saKey) {
  if (!uri || !saName || !saKey) {
    throw new Error("Missing required parameter");
  }

  var encoded = encodeURIComponent(uri);
  var now = new Date();

  // Token validity: 1 week
  var week = 60 * 60 * 24 * 7; // in seconds
  var ttl = Math.round(now.getTime() / 1000) + week;

  // String to sign
  var signature = encoded + '\n' + ttl;

  // HMAC-SHA256 using OIC built-in function
  var hashCode_value = oic.crypto.hmacsha256(signature, saKey);

  // SAS Token format
  var sasToken =
    "SharedAccessSignature sr=" + encoded +
    "&sig=" + hexToBase64UrlEncoded(hashCode_value) +
    "&se=" + ttl +
    "&skn=" + saName;

  return sasToken;
}