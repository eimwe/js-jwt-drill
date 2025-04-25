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
