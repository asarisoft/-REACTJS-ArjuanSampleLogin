import React, { useState } from "react";

// --- Helper Base64 ---
function buf2base64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function base642buf(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

// --- Hardcoded AES-GCM Key (32 byte) ---
const hardcodedKey = new TextEncoder().encode("1234567890abcdef"); 

async function getKey() {
  return await window.crypto.subtle.importKey(
    "raw",
    hardcodedKey,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptData(data) {
  const key = await getKey();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  return {
    iv: buf2base64(iv),
    ct: buf2base64(ciphertext),
  };
}

async function decryptData(encrypted) {
  const key = await getKey();
  const iv = base642buf(encrypted.iv);
  const ciphertext = base642buf(encrypted.ct);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

export default function App() {
  const [url, setUrl] = useState("");
  const [decrypted, setDecrypted] = useState(null);

  const handleEncrypt = async () => {
    const payload = {
      username: "imam",
      password: "imam1234",
      password_keycloak: "imam1234",
    };

    const encrypted = await encryptData(payload);
    const tokenStr = JSON.stringify(encrypted);
    const tokenB64 = btoa(tokenStr);

    const finalUrl = `https://arjuna-kms.netlify.app/callback?token=${encodeURIComponent(
      tokenB64
    )}`;
    setUrl(finalUrl);
  };

  const handleDecrypt = async () => {
    if (!url) return;
    const tokenB64 = decodeURIComponent(url.split("token=")[1]);
    const encrypted = JSON.parse(atob(tokenB64));
    const data = await decryptData(encrypted);
    setDecrypted(data);
  };

  return (
    <div style={{ padding: 20, fontFamily: "sans-serif" }}>
      <h2>AES-GCM Encrypt/Decrypt Demo</h2>

      <button onClick={handleEncrypt}>Generate Token</button>
      {url && (
        <div style={{ marginTop: 10 }}>
          <p style={{ wordBreak: "break-all" }}>{url}</p>
          <button onClick={handleDecrypt}>Test Decrypt</button>
        </div>
      )}

      {decrypted && (
        <pre style={{ background: "#f0f0f0", padding: 10, marginTop: 10 }}>
{JSON.stringify(decrypted, null, 2)}
        </pre>
      )}
    </div>
  );
}
