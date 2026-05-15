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
