/**
 * WebAuthn / Passkey Utilities
 *
 * Helpers for registering and verifying WebAuthn credentials for
 * beneficiary multi-factor authentication during inheritance claims.
 *
 * Falls back to email TOTP when hardware key is absent or the
 * browser does not support the Web Authentication API.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface RegisteredCredential {
  credentialId: string;
  publicKey: string;
}

export interface WebAuthnRegistrationResult {
  credentialId: string;
  rawId: ArrayBuffer;
  clientDataJSON: ArrayBuffer;
  attestationObject: ArrayBuffer;
}

export interface WebAuthnVerificationResult {
  credentialId: string;
  rawId: ArrayBuffer;
  authenticatorData: ArrayBuffer;
  clientDataJSON: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle: ArrayBuffer | null;
}

// ─── Availability check ──────────────────────────────────────────────────────

/**
 * Returns true if the current browser environment supports WebAuthn.
 */
export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable ===
      "function"
  );
}

/**
 * Returns true if a platform authenticator (Touch ID, Windows Hello, etc.)
 * is available on this device.
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  try {
    return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// ─── Buffer helpers ──────────────────────────────────────────────────────────

/**
 * Converts a base64url string to an ArrayBuffer.
 */
function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + "=".repeat(padLen);
  const binary = atob(padded);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buffer;
}

/**
 * Converts an ArrayBuffer to a base64url string.
 */
function bufferToBase64Url(buffer: ArrayBuffer): string {
  const view = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < view.length; i++) {
    binary += String.fromCharCode(view[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ─── Challenge generation ────────────────────────────────────────────────────

/**
 * Generates a cryptographically random challenge as an ArrayBuffer.
 */
function generateChallenge(length: number = 32): ArrayBuffer {
  const buffer = new ArrayBuffer(length);
  const view = new Uint8Array(buffer);
  crypto.getRandomValues(view);
  return buffer;
}

/**
 * Generates a random user id for WebAuthn registration.
 */
function generateUserId(length: number = 16): ArrayBuffer {
  const buffer = new ArrayBuffer(length);
  const view = new Uint8Array(buffer);
  crypto.getRandomValues(view);
  return buffer;
}

// ─── Registration ─────────────────────────────────────────────────────────────

/**
 * Registers a new WebAuthn credential (passkey) for a beneficiary.
 *
 * @param beneficiaryEmail - The beneficiary's email, used as the user identifier.
 * @param beneficiaryName   - Display name for the credential.
 * @returns Registration result containing the credential id and attestation data.
 */
export async function registerWebAuthnCredential(
  beneficiaryEmail: string,
  beneficiaryName: string
): Promise<WebAuthnRegistrationResult> {
  if (!isWebAuthnSupported()) {
    throw new Error("WebAuthn is not supported in this browser.");
  }

  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: generateChallenge(),
    rp: {
      name: "InheritX",
      id: window.location.hostname,
    },
    user: {
      id: generateUserId(),
      name: beneficiaryEmail,
      displayName: beneficiaryName || beneficiaryEmail,
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256
      { type: "public-key", alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
      residentKey: "required",
    },
    timeout: 60000,
    attestation: "none",
  };

  const credential = (await navigator.credentials.create({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Passkey registration was cancelled or failed.");
  }

  const rawId = credential.rawId;
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    credentialId: credential.id,
    rawId,
    clientDataJSON: response.clientDataJSON,
    attestationObject: response.attestationObject,
  };
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verifies an existing WebAuthn credential (passkey) for a claim.
 *
 * @param credentialId - The base64url-encoded credential id from registration.
 * @returns Verification result containing authenticator data and signature.
 */
export async function verifyWebAuthnCredential(
  credentialId: string
): Promise<WebAuthnVerificationResult> {
  if (!isWebAuthnSupported()) {
    throw new Error("WebAuthn is not supported in this browser.");
  }

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: generateChallenge(),
    allowCredentials: [
      {
        id: base64UrlToBuffer(credentialId),
        type: "public-key",
        transports: ["internal", "hybrid"],
      },
    ],
    userVerification: "required",
    timeout: 60000,
  };

  const assertion = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!assertion) {
    throw new Error("Passkey verification was cancelled or failed.");
  }

  const response = assertion.response as AuthenticatorAssertionResponse;

  return {
    credentialId: assertion.id,
    rawId: assertion.rawId,
    authenticatorData: response.authenticatorData,
    clientDataJSON: response.clientDataJSON,
    signature: response.signature,
    userHandle: response.userHandle,
  };
}

// ─── Local storage persistence ───────────────────────────────────────────────

const STORAGE_KEY = "inheritx_webauthn_credentials";

/**
 * Stores a registered credential id locally, keyed by beneficiary email.
 */
export function storeCredential(
  beneficiaryEmail: string,
  credentialId: string
): void {
  if (typeof window === "undefined") return;
  const existing = getAllStoredCredentials();
  existing[beneficiaryEmail] = { credentialId };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));
}

/**
 * Retrieves a stored credential id for a beneficiary.
 */
export function getStoredCredential(
  beneficiaryEmail: string
): string | null {
  if (typeof window === "undefined") return null;
  const all = getAllStoredCredentials();
  return all[beneficiaryEmail]?.credentialId ?? null;
}

/**
 * Returns true if a passkey has been registered for this beneficiary.
 */
export function hasRegisteredPasskey(beneficiaryEmail: string): boolean {
  return getStoredCredential(beneficiaryEmail) !== null;
}

/**
 * Removes a stored credential (e.g. after a successful claim).
 */
export function clearStoredCredential(beneficiaryEmail: string): void {
  if (typeof window === "undefined") return;
  const all = getAllStoredCredentials();
  delete all[beneficiaryEmail];
  localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
}

function getAllStoredCredentials(): Record<string, { credentialId: string }> {
  if (typeof window === "undefined") return {};
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
  } catch {
    return {};
  }
}

// ─── Serialization helpers for API transmission ──────────────────────────────

/**
 * Serializes a verification result into a base64url-encoded payload
 * suitable for sending to the backend.
 */
export function serializeVerificationResult(
  result: WebAuthnVerificationResult
): {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  userHandle: string | null;
} {
  return {
    credentialId: result.credentialId,
    authenticatorData: bufferToBase64Url(result.authenticatorData),
    clientDataJSON: bufferToBase64Url(result.clientDataJSON),
    signature: bufferToBase64Url(result.signature),
    userHandle: result.userHandle ? bufferToBase64Url(result.userHandle) : null,
  };
}
