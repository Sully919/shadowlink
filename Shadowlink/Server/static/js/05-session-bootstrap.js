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
