import React, { useMemo, useState } from "react";

// --- Helper Base64 ---
function buf2base64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base642buf(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

// --- Hardcoded AES-GCM Key ---
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
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );
  const object = {
    iv: buf2base64(iv),
    data: buf2base64(encryptedBuffer),
  };
  const tokenStr = JSON.stringify(object);
  const tokenB64 = btoa(tokenStr);
  return tokenB64;
}

async function decryptData(encrypted) {
  const key = await getKey();
  const iv = base642buf(encrypted.iv);
  const encryptedData = base642buf(encrypted.data);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encryptedData
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

export default function App() {
  // const targetUrl = "https://bawanaapp.netlify.app/arjuna-web-callback"

  // const targetUrl = "https://arjuna-kms.netlify.app"
  const targetUrl = "https://arjuna-lms-stg.netlify.app"

  // const targetUrl = "http://localhost:3000"
  // const targetUrl = "http://localhost:3001"
  const [username, setUsername] = useState("tester1");
  const [password, setPassword] = useState("Password!234");
  const [passwordKeycloak, setPasswordKeycloak] = useState("Password!234");
  const [url, setUrl] = useState("");
  const [decrypted, setDecrypted] = useState(null);
  const [iframeUrlA, setIframeUrlA] = useState("");
  const [expired, setExpired] = useState(1);
  const [tokenType, setTokenType] = useState("arjuna_web");
  const [targetDomain, setTargetDomain] = useState(targetUrl);

  const suggestions = useMemo(
    () => [
      {
        label: "USER 1",
        data: { username: "tester1", password: "Password!234", passwordKeycloak: "Password!234" },
      },
      {
        label: "USER 2",
        data: { username: "tester2", password: "Password!234", passwordKeycloak: "Password!234" },
      },
    ],
    []
  );

  const handleUseSuggestion = (s) => {
    setUsername(s.username);
    setPassword(s.password);
    setPasswordKeycloak(s.passwordKeycloak);
  };

  const handleEncrypt = async () => {
    const expired_second = expired * 60
    const expired_at = new Date(Date.now() + expired_second * 1000).toISOString();
    const payload = {
      username, password, password_keycloak: passwordKeycloak,
      expired_at, token_type: tokenType
    };
    const encrypted = await encryptData(payload);
    setUrl(`${targetDomain}/arjuna-callback?token=${encodeURIComponent(encrypted)}`);
    setDecrypted(null);
  };

  // from datetime import datetime, timezone
  // # ubah string ISO UTC jadi datetime object
  // expired_dt = datetime.fromisoformat(expired_at.replace("Z", "+00:00"))
  // # waktu sekarang UTC
  // now = datetime.now(timezone.utc)
  // if now > expired_dt:
  //     print("Token sudah expired")
  // else:
  //     print("Token masih berlaku")

  const handleDecrypt = async () => {
    if (!url) return;
    const tokenParam = url.split("token=")[1];
    if (!tokenParam) return;
    const tokenB64 = decodeURIComponent(tokenParam);
    const encrypted = JSON.parse(atob(tokenB64));
    const data = await decryptData(encrypted);
    setDecrypted(data);
  };

  const handleOpenUrl = () => { if (url) window.open(url, "_blank"); };
  const handleOpenIframeA = () => { if (url) setIframeUrlA(url); };

  const containerStyle = { maxWidth: 900, margin: "20px auto", fontFamily: "Inter, sans-serif" };
  const sectionStyle = { background: "#fff", padding: 20, borderRadius: 10, boxShadow: "0 3px 6px rgba(0,0,0,0.1)", marginBottom: 20 };
  const inputStyle = { width: "100%", padding: 10, borderRadius: 6, border: "1px solid #ccc", marginBottom: 10 };
  const buttonStyle = { padding: "10px 16px", borderRadius: 6, border: "none", cursor: "pointer", background: "#4f46e5", color: "#fff", marginRight: 10, marginTop: 10 };
  const secondaryButton = { ...buttonStyle, background: "#6b7280" };
  const labelStyle = { width: "100%", fontSize: '12px', marginTop: '10px', marginBottom: '4px' };

  return (
    <div style={containerStyle}>
      <h1 style={{ marginBottom: 20, color: "#111827" }}>ARJUNA WEB LOGIN DEMO</h1>

      {/* --- Form Section --- */}
      <div style={sectionStyle}>
        <h2 style={{ marginBottom: 15 }}>Form Input</h2>
        <p style={labelStyle}>Username</p>
        <input style={inputStyle} placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
        <p style={labelStyle}>Password Django</p>
        <input style={inputStyle} placeholder="Password Django" value={password} onChange={e => setPassword(e.target.value)} />
        <p style={labelStyle}>Password KeyCloak</p>
        <input style={inputStyle} placeholder="Password Keycloak" value={passwordKeycloak} onChange={e => setPasswordKeycloak(e.target.value)} />
        <p style={labelStyle}>DOMAIN (LOG+ / KMS) </p>
        <input style={inputStyle} type="text" placeholder="Token Type" value={targetDomain}
          onChange={e => setTargetDomain(e.target.value)} />

        <p style={labelStyle}>Expired (minute)</p>
        <input style={inputStyle} type="number" placeholder="Expired" value={expired} onChange={e => setExpired(e.target.value)} />
        <p style={labelStyle}>Token Type</p>
        <input style={inputStyle} type="text" placeholder="Token Type" value={tokenType} />
      </div>

      {/* --- Suggestions Section --- */}
      <div style={sectionStyle}>
        <h2 style={{ marginBottom: 10 }}>Saran Cepat</h2>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          {suggestions.map((s, idx) => (
            <button key={idx} style={secondaryButton} onClick={() => handleUseSuggestion(s.data)}>
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* --- Actions Section --- */}
      <div style={sectionStyle}>
        <h2 style={{ marginBottom: 15 }}>Actions</h2>
        <button style={buttonStyle} onClick={handleEncrypt}>1. Generate Token</button>
        <button style={buttonStyle} onClick={handleDecrypt} disabled={!url}>2. Test Decrypt Token</button>
        <button style={buttonStyle} onClick={handleOpenUrl} disabled={!url}>3. Open In Tab</button>
        <button style={buttonStyle} onClick={handleOpenIframeA} disabled={!url}>4. Open in Iframe</button>
        {url && <p style={{ wordBreak: "break-all", marginTop: 10, background: "#f3f4f6", padding: 10, borderRadius: 6 }}>{url}</p>}
        {decrypted && <pre style={{ background: "#f3f4f6", padding: 10, borderRadius: 6, marginTop: 10 }}>{JSON.stringify(decrypted, null, 2)}</pre>}
      </div>

      {/* --- Iframe Section --- */}
      <div style={sectionStyle}>
        <h2 style={{ marginBottom: 10 }}>Iframe Preview</h2>
        <h5 style={{ color: "#2563eb", marginBottom: 10 }}>INFO: BUTTON LXP MUNGKIN BLOCK X-Frame</h5>
        <iframe src={iframeUrlA} title="iframe-a" style={{ width: "100%", height: 500, borderRadius: 10, border: "1px solid #ccc" }} />
      </div>
    </div>
  );
}
