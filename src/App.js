import React, { useState } from "react";

// --- Helper Base64 ---
function buf2base64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function base642buf(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

// --- Hardcoded AES-GCM Key (16 byte untuk AES-128) ---
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
  const [iframeUrl, setIframeUrl] = useState("");

  const handleEncrypt = async () => {
    const payload = {
      username: "imam",
      password: "Savoir#2020",
      password_keycloak: "imam1234",
    };

    const encrypted = await encryptData(payload);
    const tokenStr = JSON.stringify(encrypted);
    const tokenB64 = btoa(tokenStr);

    const finalUrl = `http://localhost:3000/arjuna-web-callback?token=${encodeURIComponent(
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

  const handleOpenUrl = () => {
    if (url) {
      window.open(url, "_blank");
    }
  };

  const handleOpenIframe = () => {
    if (url) {
      setIframeUrl(url);
    }
  };

  return (
    <div style={{ padding: 20, fontFamily: "sans-serif" }}>
      <h2>ARJUNA WEB SAMPLE LOGIN DEMO</h2>

      <button onClick={handleEncrypt}>Generate Token</button>
      {url && (
        <div style={{ marginTop: 10 }}>
          <p style={{ wordBreak: "break-all" }}>{url}</p>

          <button onClick={handleDecrypt}>Test Decrypt</button>
          <button onClick={handleOpenUrl} style={{ marginLeft: 8 }}>
            Open URL
          </button>
          <button onClick={handleOpenIframe} style={{ marginLeft: 8 }}>
            Open URL in Iframe
          </button>
        </div>
      )}

      {decrypted && (
        <pre style={{ background: "#f0f0f0", padding: 10, marginTop: 10 }}>
          {JSON.stringify(decrypted, null, 2)}
        </pre>
      )}

      {iframeUrl && (
        <div style={{ marginTop: 20 }}>
          <h3>Iframe Preview</h3>
          <iframe
            src={iframeUrl}
            title="callback iframe"
            style={{ width: "100%", height: "400px", border: "1px solid #ccc" }}
          />
        </div>
      )}
    </div>
  );
}
