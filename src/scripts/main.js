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

// Verify JWT function
async function verifyJWT(token, publicKey) {
  // Split the JWT into parts
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");

  // Create signature input (header + payload)
  const signatureInput = `${encodedHeader}.${encodedPayload}`;

  // Decode the signature from base64url
  const signatureBase64 = encodedSignature
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padding = "=".repeat((4 - (signatureBase64.length % 4)) % 4);
  const signatureStr = atob(signatureBase64 + padding);
  const signature = new Uint8Array(signatureStr.length);
  for (let i = 0; i < signatureStr.length; i++) {
    signature[i] = signatureStr.charCodeAt(i);
  }

  // Verify the signature
  const isValid = await window.crypto.subtle.verify(
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    publicKey,
    signature,
    stringToUint8Array(signatureInput)
  );

  if (!isValid) {
    return { valid: false, payload: null };
  }

  // Decode the payload
  const payloadBase64 = encodedPayload.replace(/-/g, "+").replace(/_/g, "/");
  const payloadPadding = "=".repeat((4 - (payloadBase64.length % 4)) % 4);
  const payloadStr = atob(payloadBase64 + payloadPadding);
  const payload = JSON.parse(payloadStr);

  return { valid: true, payload };
}
