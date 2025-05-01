// Utility functions for base64url encoding/decoding
function base64UrlEncode(data) {
  if (typeof data === "string") {
    data = new TextEncoder().encode(data);
  }
  const base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(base64Url) {
  const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// Generate key pair for encryption
async function generateEncryptionKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// Create JWE
async function createJWE(payload, publicKey) {
  try {
    // Generate a random content encryption key (CEK)
    const cek = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // Export the CEK in raw format for encryption
    const exportedCek = await crypto.subtle.exportKey("raw", cek);

    // Encrypt the CEK with RSA-OAEP
    const encryptedKey = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      exportedCek
    );

    // Encrypt the payload with AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedPayload = new TextEncoder().encode(JSON.stringify(payload));
    const encryptedResult = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: 128,
      },
      cek,
      encodedPayload
    );

    // Extract ciphertext and tag from the result
    const ciphertext = encryptedResult.slice(
      0,
      encryptedResult.byteLength - 16
    );
    const tag = encryptedResult.slice(encryptedResult.byteLength - 16);

    // Construct JWE (compact serialization)
    const protectedHeader = base64UrlEncode(
      JSON.stringify({
        alg: "RSA-OAEP",
        enc: "A256GCM",
        kid: "1", // Optional key ID
      })
    );

    const jweParts = [
      protectedHeader,
      base64UrlEncode(encryptedKey),
      base64UrlEncode(iv),
      base64UrlEncode(ciphertext),
      base64UrlEncode(tag),
    ];

    return jweParts.join(".");
  } catch (error) {
    console.error("Error in createJWE:", error);
    throw error;
  }
}

// Decrypt JWE
async function decryptJWE(jwe, privateKey) {
  try {
    const parts = jwe.split(".");
    if (parts.length !== 5) {
      throw new Error("Invalid JWE format");
    }

    const [protectedHeader, encryptedKey, iv, ciphertext, tag] = parts;

    // Decode the protected header to get algorithms
    const header = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(protectedHeader))
    );

    if (header.alg !== "RSA-OAEP" || header.enc !== "A256GCM") {
      throw new Error("Unsupported algorithm");
    }

    // Decrypt the CEK with RSA-OAEP
    const decryptedKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64UrlDecode(encryptedKey)
    );

    // Import the CEK
    const cek = await crypto.subtle.importKey(
      "raw",
      decryptedKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // Combine ciphertext and tag for decryption
    const ciphertextBytes = base64UrlDecode(ciphertext);
    const tagBytes = base64UrlDecode(tag);
    const encryptedData = new Uint8Array(
      ciphertextBytes.byteLength + tagBytes.byteLength
    );
    encryptedData.set(new Uint8Array(ciphertextBytes), 0);
    encryptedData.set(new Uint8Array(tagBytes), ciphertextBytes.byteLength);

    // Decrypt the payload
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64UrlDecode(iv),
        tagLength: 128,
      },
      cek,
      encryptedData
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch (error) {
    console.error("Error in decryptJWE:", error);
    throw error;
  }
}
