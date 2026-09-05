const encoder = new TextEncoder();
function b64(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(value: string) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
async function key(master: string, owner: string) {
  if (master.length < 32)
    throw new Error("Data encryption key is not configured");
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(master),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(owner),
      info: encoder.encode("palisade/evidence/v1"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
export async function encrypt(value: unknown, master: string, owner: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(owner) },
    await key(master, owner),
    encoder.encode(JSON.stringify(value)),
  );
  return `v1.${b64(iv)}.${b64(new Uint8Array(ciphertext))}`;
}
export async function decrypt<T>(
  value: string,
  master: string,
  owner: string,
): Promise<T> {
  const [version, iv, data] = value.split(".");
  if (version !== "v1" || !iv || !data)
    throw new Error("Invalid encrypted record");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(iv), additionalData: encoder.encode(owner) },
    await key(master, owner),
    unb64(data),
  );
  return JSON.parse(new TextDecoder().decode(plain)) as T;
}
export async function hashToken(value: string) {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(value)),
    ),
  ]
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
}
export function randomToken() {
  return (
    "pal_" +
    b64(crypto.getRandomValues(new Uint8Array(32)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "")
  );
}
