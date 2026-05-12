/* =========================================================
   SERVER
========================================================= */
const server = "https://arrest-partly-wired.ngrok-free.dev";


/* =========================================================
   USERNAME
========================================================= */
function getUsername() {
    let name = sessionStorage.getItem("username");

    if (!name) {
        const words = ["Paragon", "Mirage", "Axis", "Cyclops", "Leshy", "Everclear"];
        const suffix = Math.floor(Math.random() * 1000);

        name = words[Math.floor(Math.random() * words.length)] + suffix;
        sessionStorage.setItem("username", name);
    }

    return name;
}

const username = getUsername();


/* =========================================================
   RSA KEYPAIR (identity only)
========================================================= */
let privateKey;
let publicKey;

async function initKeys() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );

    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;
}


/* =========================================================
   EXPORT PUBLIC KEY
========================================================= */
async function exportPublicKey() {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}


/* =========================================================
   REGISTER USER
========================================================= */
async function registerUser() {
    const pubKey = await exportPublicKey();

    await fetch(server + "/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            publicKey: pubKey
        })
    });
}


/* =========================================================
   BOOTSTRAP
========================================================= */
async function bootstrap() {
    await initKeys();
    await registerUser();

    fetchMessages();
    setInterval(fetchMessages, 2000);
}

bootstrap();


/* =========================================================
   AES ENCRYPTION (message layer)
========================================================= */
async function encryptMessageAES(message) {

    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(message);

    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoded
    );

    const rawKey = await crypto.subtle.exportKey("raw", key);

    return {
        key: rawKey,
        iv,
        data: ciphertext
    };
}


/* =========================================================
   RSA WRAP AES KEY
========================================================= */
async function wrapAESKey(aesKeyBuffer, recipientPublicKeyBase64) {

    const binary = Uint8Array.from(
        atob(recipientPublicKeyBase64),
        c => c.charCodeAt(0)
    );

    const rsaKey = await crypto.subtle.importKey(
        "spki",
        binary.buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );

    const encryptedKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKey,
        aesKeyBuffer
    );

    return encryptedKey;
}


/* =========================================================
   SEND MESSAGE (HYBRID ENCRYPTION)
========================================================= */
async function sendMessage(recipient, message) {

    const res = await fetch(server + "/user/" + recipient);
    const userData = await res.json();

    if (!userData.publicKey) {
        alert("Recipient not found");
        return;
    }

    const aesPackage = await encryptMessageAES(message);

    const wrappedKey = await wrapAESKey(
        aesPackage.key,
        userData.publicKey
    );

    const payload = {
        key: Array.from(new Uint8Array(wrappedKey)),
        iv: Array.from(aesPackage.iv),
        data: Array.from(new Uint8Array(aesPackage.data))
    };

    await fetch(server + "/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sender: username,
            recipient,
            payload,
            timestamp: Date.now()
        })
    });

    document.getElementById("message").value = "";
}


/* =========================================================
   DECRYPT MESSAGE
========================================================= */
async function decryptMessage(payload) {

    // 1. unwrap AES key
    const encryptedKey = new Uint8Array(payload.key);

    const rawKey = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKey
    );

    const aesKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    // 2. decrypt message
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: new Uint8Array(payload.iv)
        },
        aesKey,
        new Uint8Array(payload.data)
    );

    return new TextDecoder().decode(decrypted);
}


/* =========================================================
   FETCH MESSAGES
========================================================= */
async function fetchMessages() {
    const res = await fetch(server + "/messages");
    const data = await res.json();

    const container = document.getElementById("messages");
    container.innerHTML = "";

    for (const msg of data) {

        const div = document.createElement("div");

        let text = "[encrypted]";

        if (msg.recipient === username) {
            try {
                text = await decryptMessage(msg.payload);
            } catch (e) {
                text = "[decrypt failed]";
            }
        }

        div.textContent = `${msg.sender} → ${msg.recipient}: ${text}`;
        container.appendChild(div);
    }
}