// JWT Asymmetric Cryptography Demo
// This demonstrates generating and verifying JWTs using RSA (RS256) in the browser

// Generate RSA key pair
async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: { name: "SHA-256" },
    },
    true, // extractable
    ["sign", "verify"]
  );

  return keyPair;
}

// Functions to encode/decode base64url
function base64UrlEncode(data) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function stringToUint8Array(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

// Create JWT function
async function createJWT(payload, privateKey) {
  // Create header
  const header = {
    alg: "RS256",
    typ: "JWT",
  };

  // Encode header and payload
  const encodedHeader = base64UrlEncode(
    stringToUint8Array(JSON.stringify(header))
  );
  const encodedPayload = base64UrlEncode(
    stringToUint8Array(JSON.stringify(payload))
  );

  // Create signature input
  const signatureInput = `${encodedHeader}.${encodedPayload}`;

  // Sign the JWT
  const signature = await window.crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    privateKey,
    stringToUint8Array(signatureInput)
  );

  // Encode signature
  const encodedSignature = base64UrlEncode(signature);

  // Return complete JWT
  return `${signatureInput}.${encodedSignature}`;
}
