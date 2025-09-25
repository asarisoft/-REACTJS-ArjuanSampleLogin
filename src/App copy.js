import React, { useEffect, useMemo, useState } from "react";

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

// async function encryptData(data) {
//   const key = await getKey();
//   const iv = window.crypto.getRandomValues(new Uint8Array(12));
//   const encoded = new TextEncoder().encode(JSON.stringify(data));
//   const ciphertext = await window.crypto.subtle.encrypt(
//     { name: "AES-GCM", iv },
//     key,
//     encoded
//   );
//   return { iv: buf2base64(iv), ct: buf2base64(ciphertext) };
// }

async function encryptData(data) {
  const key = await getKey();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));  // 12-byte IV for AES-GCM
  const encoded = new TextEncoder().encode(JSON.stringify(data));  // Convert data to bytes
  
  // Perform AES-GCM encryption
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  // Get the authentication tag (last 16 bytes of the ciphertext)
  const authTag = ciphertext.slice(-16);  // AES-GCM tag is 16 bytes
  
  // Return the IV, ciphertext, and authentication tag
  return { 
    iv: buf2base64(iv), 
    ct: buf2base64(ciphertext.slice(0, ciphertext.length - 16)),  // Exclude the tag from ciphertext
    authTag: buf2base64(authTag)  // Include the auth tag separately
  };
}

// async function decryptData(encrypted) {
//   const key = await getKey();
//   const iv = base642buf(encrypted.iv);
//   const ciphertext = base642buf(encrypted.ct);
//   const decrypted = await window.crypto.subtle.decrypt(
//     { name: "AES-GCM", iv },
//     key,
//     ciphertext
//   );
//   return JSON.parse(new TextDecoder().decode(decrypted));
// }

// with tag
async function decryptData(encrypted) {
  const key = await getKey();

  // Convert base64 strings to buffer (for iv, ciphertext, and authentication tag)
  const iv = base642buf(encrypted.iv);
  const ciphertext = base642buf(encrypted.ct);
  const authTag = base642buf(encrypted.authTag);  // Authentication tag

  // AES-GCM requires the tag to be passed in the decryption process
  const combinedCiphertext = new Uint8Array([...ciphertext, ...authTag]);

  // Perform AES-GCM decryption
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },  // AES-GCM authentication tag length is 128 bits (16 bytes)
    key,
    combinedCiphertext
  );

  // Decode and return the decrypted data
  return JSON.parse(new TextDecoder().decode(decrypted));
}


export default function App() {
  // --- Default pakai USER 1 ---
  const [username, setUsername] = useState("imam");
  const [password, setPassword] = useState("Savoir#2020");
  const [passwordKeycloak, setPasswordKeycloak] = useState("imam1234");
  // const [callbackBase, setCallbackBase] = useState(
  //   "http://localhost:3000/arjuna-web-callback"
  // );

  const [callbackBase, setCallbackBase] = useState(
    "https://bawanaapp.netlify.app/arjuna-web-callback"
  );


  const [url, setUrl] = useState("");
  const [decrypted, setDecrypted] = useState(null);

  const [iframeUrlA, setIframeUrlA] = useState("");
  const [iframeUrlB, setIframeUrlB] = useState("");

  const [lastMessage, setLastMessage] = useState(null);

  // --- Listener umum postMessage ---
  useEffect(() => {
    const handler = (evt) => {
      console.log("📩 Message diterima dari iframe:", evt.data);
      setLastMessage(evt.data);

      // contoh, kalau iframe kirim event auto_login_done
      if (evt.data?.event === "auto_login_done" && evt.data?.url) {
        if (evt.data?.target === "_blank") {
          window.open(evt.data.url, "_blank");
        } else {
          window.location.href = evt.data.url;
        }
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, []);

  // --- Saran akun demo ---
  const suggestions = useMemo(
    () => [
      {
        label: "USER 1",
        data: {
          username: "imam",
          password: "Savoir#2020",
          passwordKeycloak: "imam1234",
        },
      },
      {
        label: "USER 2",
        data: {
          username: "03524",
          password: "Password!234",
          passwordKeycloak: "Password!234",
        },
      },
    ],
    []
  );

  const handleUseSuggestion = (s) => {
    setUsername(s.username);
    setPassword(s.password);
    setPasswordKeycloak(s.passwordKeycloak);
  };

  // --- Generate token ---
  const handleEncrypt = async () => {
    const payload = {
      username,
      password,
      password_keycloak: passwordKeycloak,
    };
    const encrypted = await encryptData(payload);
    const tokenStr = JSON.stringify(encrypted);
    const tokenB64 = btoa(tokenStr);

    const finalUrl = `${callbackBase}?token=${encodeURIComponent(tokenB64)}`;
    setUrl(finalUrl);
    setDecrypted(null);
  };

  // --- Decrypt token ---
  const handleDecrypt = async () => {
    if (!url) return;
    const tokenParam = url.split("token=")[1];
    if (!tokenParam) return;
    const tokenB64 = decodeURIComponent(tokenParam);
    const encrypted = JSON.parse(atob(tokenB64));
    const data = await decryptData(encrypted);
    setDecrypted(data);
  };

  // --- Open di tab baru ---
  const handleOpenUrl = () => {
    if (url) window.open(url, "_self");
  };

  // --- Open iframe normal ---
  const handleOpenIframeA = () => {
    if (url) setIframeUrlA(url);
  };

  return (
    <div style={{ padding: 20, fontFamily: "sans-serif" }}>
      <h2>ARJUNA WEB SAMPLE LOGIN</h2>

      {/* --- Form Input --- */}
      <div
        style={{
          display: "grid",
          gap: 10,
          gridTemplateColumns: "1fr 1fr",
          marginBottom: 12,
        }}
      >
        <div>
          <label>Username</label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="masukkan username"
            style={{ width: "100%", padding: 8 }}
          />
        </div>
        <div>
          <label>Password Django</label>
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="masukkan password"
            style={{ width: "100%", padding: 8 }}
          />
        </div>
        <div>
          <label>Password (Keycloak)</label>
          <input
            value={passwordKeycloak}
            onChange={(e) => setPasswordKeycloak(e.target.value)}
            placeholder="masukkan password keycloak"
            style={{ width: "100%", padding: 8 }}
          />
        </div>
        <div>
          <label>BAWANA URL</label>
          <input
            value={callbackBase}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="masukkan password"
            style={{ width: "100%", padding: 8 }}
          />
        </div>
      </div>

      {/* --- Saran --- */}
      <div style={{ marginBottom: 16 }}>
        <strong>Gunakan saran cepat:</strong>
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          {suggestions.map((s, idx) => (
            <button
              key={idx}
              onClick={() => handleUseSuggestion(s.data)}
              style={{ padding: 4 }}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* --- Actions --- */}
      <div>
        <button onClick={handleEncrypt}>1. Generate Token</button>
        &nbsp;
        <button onClick={handleDecrypt} disabled={!url}>
          2. Test Decrypt Token (Algoritma → AES-GCM)
        </button>

        {url && (
          <p style={{ wordBreak: "break-all", background: "#fafafa", padding: 8 }}>
            {url}
          </p>
        )}
        {decrypted && (
          <pre style={{ background: "#f0f0f0", padding: 10, marginTop: 10 }}>
            {JSON.stringify(decrypted, null, 2)}
          </pre>
        )}

        <button onClick={handleOpenUrl} disabled={!url} style={{ padding: 4 }}>
          3. OPEN BAWANA IN CURRENT TAB
        </button>
        &nbsp;&nbsp;
        <button onClick={handleOpenIframeA} disabled={!url} style={{ padding: 4 }}>
          4. OPEN BAWANA IN IFRAME
        </button>
      </div>

      {/* --- Iframes --- */}
      <div style={{ marginTop: 20, flex: 1 }}>
        <h3>IFRAME</h3>
        <h5 style={{ color: 'blue' }}> INFO:  BUTTON LXP WILL FAILED X-Frame ORIGIN, </h5>
        <h5 style={{ color: 'blue' }}> BUTTON LXP BACK TO ARJUNA WILL WORK</h5>
        <iframe
          src={iframeUrlA}
          title="iframe-a"
          style={{ width: "100%", height: 700, border: "1px solid #ccc" }}
        />
      </div>

    </div>
  );
}
