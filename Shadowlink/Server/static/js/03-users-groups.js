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
