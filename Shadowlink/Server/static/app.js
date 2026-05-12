/* =========================================================
   SERVER
========================================================= */
// Empty string means "same origin", so the client works locally, through Flask,
// or behind a tunnel without hardcoding an expired ngrok URL.
const server = "";


/* =========================================================
   STATE
========================================================= */
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const selectedRecipients = new Set();

let username = null;
let encryptionPrivateKey = null;
let encryptionPublicKey = null;
let signingPrivateKey = null;
let signingPublicKey = null;
let authToken = null;
let messageRefreshId = 0;
let intervals = [];
let knownMessages = [];
let activeHistoryFilter = { type: "all" };


/* =========================================================
   SMALL HELPERS
========================================================= */
function bytesToBase64(buffer) {
    // WebCrypto returns ArrayBuffers; base64 makes them JSON-friendly.
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBytes(value) {
    // Convert stored/transmitted base64 keys and signatures back to bytes.
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

function setStatus(message) {
    // General app status near the message composer.
    document.getElementById("status").textContent = message;
}

function setLoginStatus(message) {
    // Auth-specific status shown on the locked login screen.
    document.getElementById("loginStatus").textContent = message;
}

function setUnlocked(isUnlocked) {
    // Toggle between the locked auth screen and the messaging interface.
    document.getElementById("loginPanel").classList.toggle("hidden", isUnlocked);
    document.getElementById("appPanel").classList.toggle("hidden", !isUnlocked);
    document.getElementById("logoutButton").classList.toggle("hidden", !isUnlocked);
}

function profileKey(name) {
    // Each username gets its own encrypted local identity profile.
    return `shadowlink.profile.${name}`;
}

function groupsKey() {
    // Groups are local convenience lists scoped to the logged-in user.
    return `shadowlink.groups.${username}`;
}

function authHeaders(extraHeaders = {}) {
    // Protected API routes require the bearer token issued at login/create.
    return {
        ...extraHeaders,
        Authorization: `Bearer ${authToken}`,
    };
}

function validatePassword(password) {
    // Keep password rules client-visible; server auth is a future roadmap item.
    if (password.length < 8 || password.length > 25) {
        return "Password must be 8-25 characters.";
    }
    if (!/[A-Z]/.test(password)) {
        return "Password needs at least one capital letter.";
    }
    if (!/[0-9]/.test(password)) {
        return "Password needs at least one number.";
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        return "Password needs at least one special character.";
    }

    return null;
}

function parseRecipients() {
    // The composer supports comma-separated manual entry as well as picker clicks.
    return [...new Set(
        document.getElementById("recipient").value
            .split(",")
            .map(value => value.trim())
            .filter(value => value && value !== username)
    )];
}

function syncRecipientInput() {
    // Reflect picker/group selection back into the editable recipient field.
    document.getElementById("recipient").value = [...selectedRecipients].join(", ");
}

function loadGroups() {
    // Load saved local groups; corrupt data falls back to an empty list.
    if (!username) {
        return [];
    }

    try {
        return JSON.parse(localStorage.getItem(groupsKey()) || "[]");
    } catch (error) {
        return [];
    }
}

function saveGroups(groups) {
    // Persist local groups for the current browser identity.
    localStorage.setItem(groupsKey(), JSON.stringify(groups));
}

function setHistoryFilter(filter) {
    // Switch the visible history between all traffic, one user, or one group.
    activeHistoryFilter = filter;
    const label = document.getElementById("activeFilter");
    const chatContext = document.getElementById("chatContext");

    if (filter.type === "user") {
        label.textContent = `History: ${filter.username}`;
        chatContext.textContent = `Conversation with ${filter.username}`;
    } else if (filter.type === "group") {
        label.textContent = `History: ${filter.name}`;
        chatContext.textContent = `Group traffic: ${filter.name}`;
    } else {
        label.textContent = "History: All";
        chatContext.textContent = "All message traffic";
    }

    renderMessages(knownMessages);
}

function messageMatchesFilter(message) {
    // Decide whether a fetched message belongs in the current history view.
    if (activeHistoryFilter.type === "all") {
        return true;
    }

    const recipients = message.recipients || (message.recipient ? [message.recipient] : []);

    if (activeHistoryFilter.type === "user") {
        const otherUser = activeHistoryFilter.username;
        return message.sender === otherUser || recipients.includes(otherUser);
    }

    if (activeHistoryFilter.type === "group") {
        const groupUsers = [...activeHistoryFilter.members].sort((left, right) => left.localeCompare(right));
        const messageUsers = [...new Set([message.sender, ...recipients])]
            .filter(value => value !== username)
            .sort((left, right) => left.localeCompare(right));

        return JSON.stringify(groupUsers) === JSON.stringify(messageUsers);
    }

    return true;
}

function stablePayloadKeys(keys) {
    // Sort wrapped-key entries so signatures verify after JSON round trips.
    return Object.fromEntries(
        Object.keys(keys)
            .sort((left, right) => left.localeCompare(right))
            .map(key => [key, keys[key]])
    );
}

function canonicalMessage(message) {
    // Signatures are byte-exact. Keep object order explicit so JSON storage and
    // browser differences do not create false signature failures.
    return JSON.stringify({
        sender: message.sender,
        recipients: [...message.recipients].sort((left, right) => left.localeCompare(right)),
        hiddenRecipients: message.hiddenRecipients === true,
        payload: {
            keys: stablePayloadKeys(message.payload.keys),
            iv: message.payload.iv,
            data: message.payload.data,
        },
        timestamp: message.timestamp,
    });
}

function clearTimers() {
    // Stop polling when the user logs out.
    for (const interval of intervals) {
        clearInterval(interval);
    }
    intervals = [];
}


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


/* =========================================================
   USER / KEY LOOKUP
========================================================= */
async function getRecipientKeys(recipient) {
    // Fetch public keys for encryption and signature verification.
    const response = await fetch(server + "/user/" + encodeURIComponent(recipient), {
        headers: authHeaders(),
    });

    if (!response.ok) {
        throw new Error(`${recipient} was not found`);
    }

    const userData = await response.json();
    const pinKey = `shadowlink.pin.${username}.${recipient}`;
    const currentPin = JSON.stringify({
        publicKey: userData.publicKey,
        signingPublicKey: userData.signingPublicKey,
    });
    const previousPin = localStorage.getItem(pinKey);

    // Trust-on-first-use: not perfect, but it warns if a known contact's keys
    // change unexpectedly, which is a common sign of interception or reset.
    if (previousPin && previousPin !== currentPin) {
        throw new Error(`${recipient}'s keys changed. Verify their identity before sending.`);
    }

    if (!previousPin) {
        localStorage.setItem(pinKey, currentPin);
    }

    return userData;
}

async function importEncryptionPublicKey(publicKeyBase64) {
    // Import a recipient's RSA public key for wrapping the AES message key.
    return crypto.subtle.importKey(
        "spki",
        base64ToBytes(publicKeyBase64).buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );
}

async function importSigningPublicKey(publicKeyBase64) {
    // Import a sender's ECDSA public key for signature checks.
    return crypto.subtle.importKey(
        "spki",
        base64ToBytes(publicKeyBase64).buffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
    );
}


/* =========================================================
   RECIPIENT PICKER
========================================================= */
async function fetchUsers() {
    // Refresh the side-panel recipient list from the relay.
    if (!username) {
        return;
    }

    const response = await fetch(server + "/users", {
        headers: authHeaders(),
    });

    if (!response.ok) {
        return;
    }

    const users = await response.json();
    const list = document.getElementById("userList");
    list.innerHTML = "";

    const activeUsers = users.filter(user => user.active);
    const inactiveUsers = users.filter(user => !user.active);

    if (users.length === 0) {
        list.textContent = "No known users yet.";
        return;
    }

    renderUserGroup(list, "Active", activeUsers);
    renderUserGroup(list, "Inactive", inactiveUsers);
}

function renderUserGroup(list, label, users) {
    // Render either the active or inactive user section.
    if (users.length === 0) {
        return;
    }

    const heading = document.createElement("div");
    heading.className = "user-group";
    heading.textContent = label;
    list.appendChild(heading);

    for (const user of users) {
        const button = document.createElement("button");
        const presence = document.createElement("span");

        button.className = "user-button";
        button.type = "button";
        button.textContent = user.username;
        button.setAttribute("aria-pressed", selectedRecipients.has(user.username) ? "true" : "false");

        presence.className = "presence";
        if (!user.active) {
            presence.classList.add("inactive");
        }
        presence.textContent = user.active ? "active" : "offline";
        button.appendChild(presence);

        button.addEventListener("click", () => {
            if (selectedRecipients.has(user.username)) {
                selectedRecipients.delete(user.username);
            } else {
                selectedRecipients.add(user.username);
            }

            syncRecipientInput();
            setHistoryFilter({ type: "user", username: user.username });
            fetchUsers();
        });

        list.appendChild(button);
    }
}

function renderGroups() {
    // Render locally saved group shortcuts for the current identity.
    const groupList = document.getElementById("groupList");
    const groups = loadGroups();

    groupList.innerHTML = "";

    if (groups.length === 0) {
        groupList.textContent = "No groups yet.";
        return;
    }

    for (const group of groups) {
        const button = document.createElement("button");
        const presence = document.createElement("span");

        button.className = "user-button";
        button.type = "button";
        button.textContent = group.name;
        button.setAttribute(
            "aria-pressed",
            activeHistoryFilter.type === "group" && activeHistoryFilter.name === group.name ? "true" : "false"
        );

        presence.className = "presence inactive";
        presence.textContent = `${group.members.length}`;
        button.appendChild(presence);

        button.addEventListener("click", () => {
            selectedRecipients.clear();
            for (const member of group.members) {
                selectedRecipients.add(member);
            }

            syncRecipientInput();
            setHistoryFilter({ type: "group", name: group.name, members: group.members });
            fetchUsers();
            renderGroups();
        });

        groupList.appendChild(button);
    }
}

function createGroupFromSelected() {
    // Save the currently selected recipients as a named local group.
    const name = document.getElementById("groupName").value.trim();

    selectedRecipients.clear();
    for (const recipient of parseRecipients()) {
        selectedRecipients.add(recipient);
    }

    const members = [...selectedRecipients].sort((left, right) => left.localeCompare(right));

    if (!name || members.length < 2) {
        setStatus("Name the group and select at least two users.");
        return;
    }

    const groups = loadGroups().filter(group => group.name.toLowerCase() !== name.toLowerCase());
    groups.push({ name, members });
    groups.sort((left, right) => left.name.localeCompare(right.name));
    saveGroups(groups);

    document.getElementById("groupName").value = "";
    setHistoryFilter({ type: "group", name, members });
    renderGroups();
    setStatus(`Group ${name} saved.`);
}


/* =========================================================
   ENCRYPTION
========================================================= */
async function encryptMessageAES(message) {
    // Encrypt plaintext once with a fresh AES-GCM key.
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoder.encode(message)
    );

    return {
        key: await crypto.subtle.exportKey("raw", key),
        iv,
        data: ciphertext,
    };
}

async function wrapAESKey(aesKeyBuffer, recipientPublicKeyBase64) {
    // Encrypt the AES key to one recipient's public key.
    const recipientKey = await importEncryptionPublicKey(recipientPublicKeyBase64);
    return crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientKey, aesKeyBuffer);
}

async function buildWrappedKeys(aesKeyBuffer, recipients) {
    // Build one encrypted AES key per recipient, plus the sender for history.
    const keys = {};

    for (const recipient of recipients) {
        const recipientKeys = recipient === username
            ? { publicKey: await exportPublicKey(encryptionPublicKey) }
            : await getRecipientKeys(recipient);

        keys[recipient] = Array.from(new Uint8Array(
            await wrapAESKey(aesKeyBuffer, recipientKeys.publicKey)
        ));
    }

    return keys;
}

async function decryptMessage(payload) {
    // Unwrap this user's AES key and decrypt the message body.
    const wrappedKey = payload.keys[username];

    if (!wrappedKey) {
        throw new Error("No wrapped key for this user");
    }

    const rawKey = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        encryptionPrivateKey,
        new Uint8Array(wrappedKey)
    );

    const aesKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: new Uint8Array(payload.iv),
        },
        aesKey,
        new Uint8Array(payload.data)
    );

    return decoder.decode(decrypted);
}


/* =========================================================
   SIGNING
========================================================= */
async function signEnvelope(message) {
    // Sign metadata and ciphertext so recipients can detect tampering.
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingPrivateKey,
        encoder.encode(canonicalMessage(message))
    );

    return bytesToBase64(signature);
}

async function verifyEnvelope(message, signingPublicKeyBase64) {
    // Verify that the sender's signing key produced this envelope signature.
    const key = await importSigningPublicKey(signingPublicKeyBase64);

    return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        base64ToBytes(message.signature),
        encoder.encode(canonicalMessage(message))
    );
}


/* =========================================================
   SEND MESSAGE
========================================================= */
async function postEnvelope(envelope) {
    // Attach a signature and hand the encrypted envelope to the relay.
    envelope.signature = await signEnvelope(envelope);

    const response = await fetch(server + "/send", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(envelope),
    });

    if (!response.ok) {
        const details = await response.json().catch(() => ({}));
        throw new Error(details.error || "Send failed");
    }
}

async function handleSend() {
    // Gather recipients, encrypt once, then send either group or hidden copies.
    selectedRecipients.clear();
    for (const recipient of parseRecipients()) {
        selectedRecipients.add(recipient);
    }

    const recipients = [...selectedRecipients];
    const message = document.getElementById("message").value;
    const hiddenRecipients = document.getElementById("hideRecipients").checked;

    if (recipients.length === 0 || !message.trim()) {
        setStatus("Add at least one recipient and a message first.");
        return;
    }

    try {
        setStatus("Encrypting...");

        const aesPackage = await encryptMessageAES(message);
        const ciphertext = Array.from(new Uint8Array(aesPackage.data));
        const iv = Array.from(aesPackage.iv);
        const timestamp = Date.now();

        if (hiddenRecipients) {
            // Hidden-recipient mode sends one encrypted record per recipient.
            // The relay still knows where it routes each record, but recipients
            // do not receive the full group list.
            for (const recipient of recipients) {
                const envelopeRecipients = [recipient];
                const keys = await buildWrappedKeys(aesPackage.key, [username, recipient]);

                await postEnvelope({
                    sender: username,
                    recipients: envelopeRecipients,
                    hiddenRecipients: true,
                    payload: { keys, iv, data: ciphertext },
                    timestamp,
                });
            }
        } else {
            const keys = await buildWrappedKeys(aesPackage.key, [username, ...recipients]);

            await postEnvelope({
                sender: username,
                recipients,
                hiddenRecipients: false,
                payload: { keys, iv, data: ciphertext },
                timestamp,
            });
        }

        document.getElementById("message").value = "";
        setStatus("Sent.");

        if (recipients.length === 1) {
            setHistoryFilter({ type: "user", username: recipients[0] });
        }

        await fetchMessages();
        await fetchUsers();
    } catch (error) {
        setStatus(error.message);
    }
}


/* =========================================================
   FETCH MESSAGES
========================================================= */
async function fetchMessages() {
    // Pull encrypted traffic involving this user from the relay.
    if (!username) {
        return;
    }

    const refreshId = ++messageRefreshId;
    const response = await fetch(server + "/messages?username=" + encodeURIComponent(username), {
        headers: authHeaders(),
    });

    if (!response.ok) {
        setStatus("Could not load messages.");
        return;
    }

    knownMessages = await response.json();
    await renderMessages(knownMessages, refreshId);
}

async function renderMessages(messages, refreshId = messageRefreshId) {
    // Decrypt and display the current filtered history without flicker.
    const nextMessages = document.createDocumentFragment();

    for (const message of messages.filter(messageMatchesFilter)) {
        const div = document.createElement("div");
        const meta = document.createElement("div");
        const body = document.createElement("div");

        div.className = "message";
        meta.className = "meta";

        const recipients = message.recipients || (message.recipient ? [message.recipient] : []);
        const when = new Date(message.timestamp).toLocaleString();
        const recipientText = message.hiddenRecipients && message.sender !== username
            ? "recipient list hidden"
            : recipients.join(", ");
        meta.textContent = `${message.sender} -> ${recipientText} | ${when}`;

        if (message.sender === username || recipients.includes(username)) {
            try {
                const senderKeys = await getRecipientKeys(message.sender);
                const normalizedMessage = { ...message, recipients };
                const verified = await verifyEnvelope(normalizedMessage, senderKeys.signingPublicKey);
                const plaintext = await decryptMessage(message.payload);

                body.textContent = verified ? plaintext : "[signature failed]";
            } catch (error) {
                body.textContent = "[decrypt failed]";
            }
        } else {
            body.textContent = "[encrypted]";
        }

        div.appendChild(meta);
        div.appendChild(body);
        nextMessages.appendChild(div);
    }

    if (refreshId !== messageRefreshId) {
        return;
    }

    document.getElementById("messages").replaceChildren(nextMessages);
}


/* =========================================================
   LOGIN / LOGOUT
========================================================= */
async function finishUnlock() {
    // Complete UI setup after identity keys are unlocked and registered.
    document.getElementById("identity").textContent = `Unlocked as ${username}`;
    document.getElementById("createPassword").value = "";
    document.getElementById("loginPassword").value = "";
    setUnlocked(true);
    setStatus("");

    await fetchUsers();
    renderGroups();
    await fetchMessages();

    intervals = [
        setInterval(heartbeat, 15000),
        setInterval(fetchUsers, 5000),
        setInterval(fetchMessages, 2000),
    ];
}

async function handleCreateAccount() {
    // Create a brand-new local identity and register its public keys.
    const enteredUsername = document.getElementById("createUsername").value.trim();
    const password = document.getElementById("createPassword").value;

    try {
        setLoginStatus("Creating account...");
        await unlockIdentity(enteredUsername, password, "create");
        await finishUnlock();
        setStatus("Account created.");
    } catch (error) {
        if (enteredUsername) {
            localStorage.removeItem(profileKey(enteredUsername));
        }
        username = null;
        authToken = null;
        encryptionPrivateKey = null;
        encryptionPublicKey = null;
        signingPrivateKey = null;
        signingPublicKey = null;
        setLoginStatus(error.message || "Could not create account.");
    }
}

async function handleLogin() {
    // Unlock an existing local identity for this browser/profile.
    const enteredUsername = document.getElementById("loginUsername").value.trim();
    const password = document.getElementById("loginPassword").value;

    try {
        setLoginStatus("Unlocking...");
        await unlockIdentity(enteredUsername, password, "login");
        await finishUnlock();
    } catch (error) {
        username = null;
        authToken = null;
        encryptionPrivateKey = null;
        encryptionPublicKey = null;
        signingPrivateKey = null;
        signingPublicKey = null;
        setLoginStatus(error.message || "Could not unlock this identity with that username/password.");
    }
}

async function handleLogout() {
    await logoutServerAccount();
    // Clear private keys from memory and return to the locked screen.
    clearTimers();
    username = null;
    authToken = null;
    encryptionPrivateKey = null;
    encryptionPublicKey = null;
    signingPrivateKey = null;
    signingPublicKey = null;
    selectedRecipients.clear();
    messageRefreshId += 1;

    document.getElementById("identity").textContent = "Locked";
    document.getElementById("recipient").value = "";
    document.getElementById("message").value = "";
    document.getElementById("createPassword").value = "";
    document.getElementById("loginPassword").value = "";
    document.getElementById("messages").replaceChildren();
    document.getElementById("userList").textContent = "Login to see known users.";
    document.getElementById("groupList").textContent = "No groups yet.";
    document.getElementById("activeFilter").textContent = "History: All";
    document.getElementById("chatContext").textContent = "Select a user, group, or enter multiple recipients.";
    activeHistoryFilter = { type: "all" };
    knownMessages = [];
    setStatus("");
    setLoginStatus("");
    setUnlocked(false);
}


/* =========================================================
   BOOTSTRAP
========================================================= */
function bootstrap() {
    // Wire all UI controls once the static page has loaded.
    setUnlocked(false);
    document.getElementById("createAccountButton").addEventListener("click", handleCreateAccount);
    document.getElementById("loginButton").addEventListener("click", handleLogin);
    document.getElementById("logoutButton").addEventListener("click", handleLogout);
    document.getElementById("sendButton").addEventListener("click", handleSend);
    document.getElementById("createGroupButton").addEventListener("click", createGroupFromSelected);
    document.getElementById("showAllMessagesButton").addEventListener("click", () => {
        setHistoryFilter({ type: "all" });
        renderGroups();
    });
    document.getElementById("recipient").addEventListener("input", () => {
        selectedRecipients.clear();
        for (const recipient of parseRecipients()) {
            selectedRecipients.add(recipient);
        }
        fetchUsers();
    });
}

bootstrap();
