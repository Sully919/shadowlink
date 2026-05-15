/* =========================================================
   PASSWORD-LOCKED LOCAL IDENTITY
========================================================= */
async function derivePasswordKey(password, salt) {
    // Derive an AES key from the password for encrypting local identity data.
    const baseKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 250000,
            hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptProfile(profile, password, salt) {
    // Encrypt exported private/public JWKs before placing them in localStorage.
    const key = await derivePasswordKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoder.encode(JSON.stringify(profile))
    );

    return {
        salt: Array.from(salt),
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(ciphertext)),
    };
}

async function decryptProfile(storedProfile, password) {
    // Wrong passwords fail here because AES-GCM authentication will reject them.
    const key = await derivePasswordKey(password, new Uint8Array(storedProfile.salt));
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(storedProfile.iv) },
        key,
        new Uint8Array(storedProfile.data)
    );

    return JSON.parse(decoder.decode(plaintext));
}

async function createProfile(password) {
    // Create long-term encryption and signing identities for this browser/user.
    const encryptionKeys = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const signingKeys = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );

    const profile = {
        encryptionPrivateJwk: await crypto.subtle.exportKey("jwk", encryptionKeys.privateKey),
        encryptionPublicJwk: await crypto.subtle.exportKey("jwk", encryptionKeys.publicKey),
        signingPrivateJwk: await crypto.subtle.exportKey("jwk", signingKeys.privateKey),
        signingPublicJwk: await crypto.subtle.exportKey("jwk", signingKeys.publicKey),
    };

    const salt = crypto.getRandomValues(new Uint8Array(16));
    localStorage.setItem(profileKey(username), JSON.stringify(await encryptProfile(profile, password, salt)));
    return profile;
}

async function loadProfile(password) {
    // Unlock an existing local identity, or create one for a new account flow.
    const stored = localStorage.getItem(profileKey(username));

    // The password never goes to the server. It unlocks the browser's local
    // identity keys; without it, incoming/outgoing message bodies stay encrypted.
    const profile = stored
        ? await decryptProfile(JSON.parse(stored), password)
        : await createProfile(password);

    encryptionPrivateKey = await crypto.subtle.importKey(
        "jwk",
        profile.encryptionPrivateJwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );
    encryptionPublicKey = await crypto.subtle.importKey(
        "jwk",
        profile.encryptionPublicJwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );
    signingPrivateKey = await crypto.subtle.importKey(
        "jwk",
        profile.signingPrivateJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
    );
    signingPublicKey = await crypto.subtle.importKey(
        "jwk",
        profile.signingPublicJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
    );
}

async function exportPublicKey(key) {
    // Public keys are shared with the relay so others can send/verify messages.
    const exported = await crypto.subtle.exportKey("spki", key);
    return bytesToBase64(exported);
}

async function unlockIdentity(enteredUsername, password, mode) {
    // Shared auth path for both "Create Account" and "Login Existing".
    const passwordError = validatePassword(password);

    if (!enteredUsername) {
        throw new Error("Enter a username.");
    }
    if (passwordError) {
        throw new Error(passwordError);
    }

    const hasLocalProfile = Boolean(localStorage.getItem(profileKey(enteredUsername)));

    if (mode === "create") {
        if (hasLocalProfile) {
            throw new Error("That account already exists in this browser. Use Login Existing.");
        }
    }

    if (mode === "login" && !hasLocalProfile) {
        throw new Error("No local identity found for that username in this browser.");
    }

    username = enteredUsername;
    await loadProfile(password);

    if (mode === "create") {
        await createServerAccount(password);
    } else {
        await loginServerAccount(password);
        await registerUser();
    }

    await heartbeat();
}


/* =========================================================
   REGISTRATION / PRESENCE
========================================================= */
async function registerUser() {
    // Publishes this browser identity's public keys to the relay.
    const response = await fetch(server + "/register", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
            username,
            publicKey: await exportPublicKey(encryptionPublicKey),
            signingPublicKey: await exportPublicKey(signingPublicKey),
        }),
    });

    if (!response.ok) {
        const details = await response.json().catch(() => ({}));
        throw new Error(details.error || "Registration failed");
    }
}

async function createServerAccount(password) {
    // Create the server-side account and receive this session's bearer token.
    const response = await fetch(server + "/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            password,
            publicKey: await exportPublicKey(encryptionPublicKey),
            signingPublicKey: await exportPublicKey(signingPublicKey),
        }),
    });

    const details = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(details.error || "Account creation failed");
    }

    authToken = details.token;
}

async function loginServerAccount(password) {
    // Authenticate with the relay. Password hashes stay server-side only.
    const response = await fetch(server + "/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
    });

    const details = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(details.error || "Login failed");
    }

    authToken = details.token;
}

async function logoutServerAccount() {
    // Best-effort token invalidation; local logout continues even if it fails.
    if (!authToken) {
        return;
    }

    await fetch(server + "/auth/logout", {
        method: "POST",
        headers: authHeaders(),
    }).catch(() => {});
}

async function heartbeat() {
    // Keeps presence fresh while the user is unlocked/logged in.
    if (!username) {
        return;
    }

    await fetch(server + "/heartbeat", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ username }),
    });
}
