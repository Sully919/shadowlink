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
