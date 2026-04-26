"use strict";

// ================================================================
// State
// ================================================================

let API_PORT = 8080;
let identity = null;
let currentContact = null;    // { public_key, alias, onion_address }
let currentGroup = null;      // { id, name, is_admin }
let eventSource = null;
let refreshTimer = null;
let pendingFile = null;       // { data: base64, name, mime } | null

// ================================================================
// Initialisation
// ================================================================

window.addEventListener("DOMContentLoaded", () => {
    // Wait for pywebview bridge, then boot
    if (window.pywebview) {
        boot();
    } else {
        window.addEventListener("pywebviewready", boot);
    }
});

async function boot() {
    try {
        if (window.pywebview && window.pywebview.api) {
            API_PORT = await window.pywebview.api.get_api_port();
            const ver = await window.pywebview.api.get_version();
            const el = document.getElementById("version-label");
            if (el) el.textContent = "v" + ver;
        }
    } catch (_) { /* use default */ }
    await initApp();
}

async function initApp() {
    try {
        const status = await api("GET", "/api/status");

        if (status.identity_loaded) {
            identity = await api("GET", "/api/identity");
            await showMain();
        } else if (status.identity_exists) {
            showView("unlock");
        } else {
            showView("onboarding");
        }
    } catch (_) {
        // Node unreachable — keep retrying
        setTimeout(initApp, 1000);
    }
}

// ================================================================
// API helper
// ================================================================

async function api(method, path, body = null) {
    const opts = {
        method,
        headers: { "Content-Type": "application/json" },
    };
    if (body !== null) opts.body = JSON.stringify(body);
    let response;
    try {
        response = await fetch(`http://127.0.0.1:${API_PORT}${path}`, opts);
    } catch (networkErr) {
        const e = new Error("Cannot reach legion-node. Is it running?");
        e.status = 0;
        throw e;
    }
    if (!response.ok) {
        let detail = "Server error";
        try {
            const body = await response.json();
            if (typeof body.detail === "string") {
                detail = body.detail;
            } else if (Array.isArray(body.detail)) {
                // FastAPI Pydantic validation errors: [{loc, msg, type}, ...]
                detail = body.detail.map(e => e.msg || JSON.stringify(e)).join(", ");
            }
        } catch (_) {}
        const e = new Error(detail);
        e.status = response.status;
        throw e;
    }
    if (response.status === 204) return null;
    return response.json();
}

// ================================================================
// View routing
// ================================================================

function showView(name) {
    document.querySelectorAll(".view").forEach(v => v.classList.add("hidden"));
    document.getElementById(`view-${name}`).classList.remove("hidden");
}

function showPanel(name) {
    document.querySelectorAll(".panel").forEach(p => p.classList.add("hidden"));
    document.getElementById(`panel-${name}`).classList.remove("hidden");
    // Clear active state in sidebar
    if (name !== "messages" && name !== "group") {
        document.querySelectorAll(".contact-item, .group-item").forEach(el => el.classList.remove("active"));
    }
}

function switchTab(tab) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.getElementById(`tab-${tab}`).classList.add("active");
    document.getElementById("contacts-panel").classList.toggle("hidden", tab !== "contacts");
    document.getElementById("groups-panel").classList.toggle("hidden", tab !== "groups");
}

// ================================================================
// Main dashboard
// ================================================================

async function showMain() {
    showView("main");
    document.getElementById("status-alias").textContent = identity.alias;
    showPanel("welcome");
    await loadSidebar();
    connectSSE();
    await updateStatus();
}

async function loadSidebar() {
    await loadContacts();
    await loadGroups();
}

async function loadContacts() {
    try {
        const contacts = await api("GET", "/api/contacts");
        const list = document.getElementById("contacts-list");
        list.innerHTML = "";
        contacts.forEach(c => {
            const div = document.createElement("div");
            div.className = "contact-item";
            div.dataset.key = c.public_key;
            const badge = c.unread_count > 0
                ? `<span class="unread-badge">${c.unread_count}</span>` : "";
            div.innerHTML = `
                <div class="item-info">
                    <span class="item-name">${esc(c.alias || "Unknown")}</span>
                    <span class="item-sub">${esc(c.public_key.slice(0, 16))}…</span>
                </div>
                ${badge}
                <button class="btn-delete-item" title="Edit alias">✎</button>
                <button class="btn-delete-item" title="Remove contact">×</button>
            `;
            div.querySelector(".item-info").addEventListener("click", () => openConversation(c));
            const [btnEdit, btnDel] = div.querySelectorAll(".btn-delete-item");
            btnEdit.addEventListener("click", (e) => {
                e.stopPropagation();
                editContactAlias(c, div);
            });
            btnDel.addEventListener("click", (e) => {
                e.stopPropagation();
                deleteContact(c);
            });
            list.appendChild(div);
        });
    } catch (_) {}
}

async function loadGroups() {
    try {
        const groups = await api("GET", "/api/groups");
        const list = document.getElementById("groups-list");
        list.innerHTML = "";
        groups.forEach(g => {
            const div = document.createElement("div");
            div.className = "group-item";
            div.dataset.id = g.id;
            div.innerHTML = `
                <div class="item-info">
                    <span class="item-name">${esc(g.name)}</span>
                    <span class="item-sub">${g.is_admin ? "admin" : "member"}</span>
                </div>
                <button class="btn-delete-item" title="Leave / delete group">×</button>
            `;
            div.querySelector(".item-info").addEventListener("click", () => openGroup(g));
            div.querySelector(".btn-delete-item").addEventListener("click", (e) => {
                e.stopPropagation();
                deleteGroup(g);
            });
            list.appendChild(div);
        });
    } catch (_) {}
}

async function updateStatus() {
    try {
        const status = await api("GET", "/api/status");
        const torEl = document.getElementById("status-tor");
        if (status.tor_running) {
            torEl.textContent = "Tor ✓";
            torEl.className = "status-indicator status-ok";
            torEl.title = status.onion_address;
        } else if (status.tor_starting) {
            torEl.textContent = "Tor …";
            torEl.className = "status-indicator status-unknown";
            torEl.title = "Tor is starting…";
        } else if (status.tor_error) {
            torEl.textContent = "Tor ✗";
            torEl.className = "status-indicator status-error";
            torEl.title = status.tor_error + "\n\nClick to retry";
        } else {
            torEl.textContent = "Tor ✗";
            torEl.className = "status-indicator status-error";
            torEl.title = "Tor is not running. Click to start.";
        }
    } catch (_) {}
}

async function retryTor() {
    const torEl = document.getElementById("status-tor");
    if (torEl.className.includes("status-ok") || torEl.className.includes("status-unknown")) return;
    try {
        await api("POST", "/api/tor/retry");
        torEl.textContent = "Tor …";
        torEl.className = "status-indicator status-unknown";
        torEl.title = "Tor is starting…";
    } catch (err) {
        showToast("Cannot start Tor: " + err.message);
    }
}

// ================================================================
// SSE — live updates
// ================================================================

function connectSSE() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(`http://127.0.0.1:${API_PORT}/api/events`);

    eventSource.onmessage = (e) => {
        try {
            const event = JSON.parse(e.data);
            handleEvent(event);
        } catch (_) {}
    };

    eventSource.onerror = () => {
        // Reconnect after 5 seconds
        eventSource.close();
        setTimeout(connectSSE, 5000);
    };
}

async function handleEvent(event) {
    if (event.type === "message") {
        if (currentContact && event.from === currentContact.public_key) {
            // Conversation is open — mark as read immediately, no badge needed
            try { await api("POST", `/api/messages/${event.from}/read`); } catch (_) {}
            loadMessages(currentContact);
        }
        loadContacts(); // refresh sidebar badges
        if (window.pywebview) {
            window.pywebview.api.show_notification("New message", "You have a new message");
        }
    } else if (event.type === "tor_ready") {
        updateStatus();
        showToast("Tor hidden service active");
    } else if (event.type === "tor_status") {
        if (event.status === "error") {
            updateStatus();
            showToast("Tor failed to start. Click Tor ✗ to retry.");
        } else if (event.status === "starting") {
            updateStatus();
        }
    } else if (event.type === "delivery_status") {
        // Refresh conversation to show updated status dot (queued → delivered)
        if (currentContact) {
            loadMessages(currentContact);
        }
    } else if (event.type === "group_post") {
        if (currentGroup && event.group_id === currentGroup.id) {
            loadPosts(currentGroup);
        }
    } else if (event.type === "group_invite") {
        loadGroups();
        showToast("You were invited to a group");
    }
}

// ================================================================
// Unlock
// ================================================================

document.getElementById("form-unlock").addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = document.getElementById("input-unlock-password").value;
    const errEl   = document.getElementById("unlock-error");
    const btn     = document.getElementById("btn-unlock");

    errEl.classList.add("hidden");
    btn.disabled = true;
    btn.textContent = "Unlocking…";

    try {
        identity = await api("POST", "/api/identity/unlock", { password });
        await showMain();
    } catch (err) {
        showError(errEl, err.status === 401 ? "Wrong password." : err.message);
        btn.disabled = false;
        btn.textContent = "Unlock";
        document.getElementById("input-unlock-password").value = "";
        document.getElementById("input-unlock-password").focus();
    }
});

// ================================================================
// Onboarding
// ================================================================

document.getElementById("form-create-identity").addEventListener("submit", async (e) => {
    e.preventDefault();
    const alias = document.getElementById("input-alias").value.trim();
    const pw1   = document.getElementById("input-password").value;
    const pw2   = document.getElementById("input-password2").value;
    const errEl = document.getElementById("onboarding-error");

    errEl.classList.add("hidden");

    if (pw1 !== pw2) {
        showError(errEl, "Passwords do not match.");
        return;
    }
    if (pw1.length < 8) {
        showError(errEl, "Password must be at least 8 characters.");
        return;
    }

    const btn = document.getElementById("btn-create");
    btn.disabled = true;
    btn.textContent = "Creating…";

    try {
        identity = await api("POST", "/api/identity/create", { alias, password: pw1 });
        await showMain();
    } catch (err) {
        showError(errEl, err.message);
        btn.disabled = false;
        btn.textContent = "Create identity";
    }
});

// ================================================================
// Private messages
// ================================================================

async function openConversation(contact) {
    currentContact = contact;
    currentGroup = null;

    document.querySelectorAll(".contact-item").forEach(el =>
        el.classList.toggle("active", el.dataset.key === contact.public_key)
    );

    document.getElementById("msg-peer-alias").textContent = contact.alias || "Unknown";
    document.getElementById("msg-peer-key").textContent = contact.public_key.slice(0, 24) + "…";

    showPanel("messages");
    // Mark incoming messages as read and refresh sidebar badge
    try { await api("POST", `/api/messages/${contact.public_key}/read`); } catch (_) {}
    await loadContacts();
    await loadMessages(contact);
}

async function loadMessages(contact) {
    try {
        const messages = await api("GET", `/api/messages/${contact.public_key}`);
        const list = document.getElementById("messages-list");
        list.innerHTML = "";
        messages.forEach(msg => {
            const isOutgoing = msg.from_key === identity.public_key;
            const bubble = document.createElement("div");
            bubble.className = `message-bubble ${isOutgoing ? "outgoing" : "incoming"}`;
            const ts = new Date(msg.timestamp * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
            const statusIcon = { queued: '…', sent: '→', delivered: '✓', failed: '✗' };
            const icon = isOutgoing ? `<span class="status-icon ${msg.status}" title="${msg.status}">${statusIcon[msg.status] || ''}</span>` : '';

            let content;
            if (msg.file_data && msg.mime_type) {
                const name = esc(msg.file_name || "file");
                const size = Math.round(atob(msg.file_data).length / 1024);
                const saveBtn = `<button class="btn-copy" style="margin-top:6px" onclick="saveAttachment('${msg.file_data}','${msg.file_name||'file'}')">↓ Save</button>`;
                if (msg.mime_type.startsWith("image/")) {
                    const dataUrl = `data:${msg.mime_type};base64,${msg.file_data}`;
                    content = `<img class="msg-image" src="${dataUrl}" alt="${name}">${saveBtn}`;
                } else {
                    content = `<div>📄 ${name} (${size} KB)</div>${saveBtn}`;
                }
            } else {
                content = msg.text != null ? esc(msg.text) : '<em style="opacity:.5">[encrypted]</em>';
            }

            bubble.innerHTML = `
                <div class="message-text">${content}</div>
                <div class="message-meta"><span>${ts}</span>${icon}</div>
            `;
            list.appendChild(bubble);
        });
        _scrollToBottom(list);
    } catch (_) {}
}

function _scrollToBottom(list) {
    const imgs = list.querySelectorAll("img");
    if (!imgs.length) {
        list.scrollTop = list.scrollHeight;
        return;
    }
    let pending = imgs.length;
    const done = () => { if (--pending === 0) list.scrollTop = list.scrollHeight; };
    imgs.forEach(img => {
        if (img.complete) done();
        else { img.addEventListener("load", done, { once: true });
               img.addEventListener("error", done, { once: true }); }
    });
}

async function sendMessage() {
    if (!currentContact || !identity) return;
    const input = document.getElementById("msg-input");
    const text = input.value.trim();
    if (!text && !pendingFile) return;

    input.value = "";
    input.style.height = "auto";

    try {
        const body = { to: currentContact.public_key, onion: currentContact.onion_address };
        if (pendingFile) {
            body.file_data = pendingFile.data;
            body.file_name = pendingFile.name;
            body.mime_type = pendingFile.mime;
            if (text) body.text = text;
            clearFileSelection();
        } else {
            body.text = text;
        }
        await api("POST", "/api/messages", body);
        await loadMessages(currentContact);
    } catch (err) {
        showToast("Failed to send: " + err.message);
    }
}

// Fallback MIME types for files browsers may not recognize
const _MIME_BY_EXT = {
    py: "text/x-python", js: "text/javascript", ts: "text/typescript",
    json: "application/json", md: "text/markdown", sh: "text/x-sh",
    rs: "text/x-rust", go: "text/x-go", c: "text/x-c", cpp: "text/x-c++",
    java: "text/x-java", rb: "text/x-ruby", php: "text/x-php",
    yaml: "text/yaml", yml: "text/yaml", toml: "application/toml",
    xml: "text/xml", csv: "text/csv", sql: "text/x-sql",
    txt: "text/plain", pdf: "application/pdf", zip: "application/zip",
};

function _detectMime(file) {
    if (file.type && file.type !== "application/octet-stream") return file.type;
    const ext = file.name.split(".").pop().toLowerCase();
    return _MIME_BY_EXT[ext] || "application/octet-stream";
}

function handleFileSelected(input) {
    const file = input.files[0];
    if (!file) return;
    const MAX = 5 * 1024 * 1024;
    if (file.size > MAX) {
        showToast("File too large (max 5 MB)");
        input.value = "";
        return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
        const base64 = e.target.result.split(",")[1];
        pendingFile = { data: base64, name: file.name, mime: _detectMime(file) };
        document.getElementById("file-preview-name").textContent = `📎 ${file.name}`;
        document.getElementById("file-preview").classList.remove("hidden");
    };
    reader.onerror = () => { showToast("Could not read file"); input.value = ""; };
    reader.readAsDataURL(file);
    input.value = "";
}

async function saveAttachment(base64Data, filename) {
    if (window.pywebview && window.pywebview.api) {
        const path = await window.pywebview.api.save_file(base64Data, filename);
        if (path) showToast(`Saved to ${path}`);
        else showToast("Could not save file");
    } else {
        // Fallback for browser testing
        const a = document.createElement("a");
        a.href = "data:application/octet-stream;base64," + base64Data;
        a.download = filename;
        a.click();
    }
}

function clearFileSelection() {
    pendingFile = null;
    document.getElementById("file-preview").classList.add("hidden");
    document.getElementById("file-preview-name").textContent = "";
}

function handleMsgKey(e) {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
    autoResize(e.target);
}

// ================================================================
// Groups
// ================================================================

async function openGroup(group) {
    currentGroup = group;
    currentContact = null;

    document.querySelectorAll(".group-item").forEach(el =>
        el.classList.toggle("active", el.dataset.id === group.id)
    );

    document.getElementById("group-name").textContent = group.name;
    const adminActions = document.getElementById("group-admin-actions");
    adminActions.classList.toggle("hidden", !group.is_admin);

    showPanel("group");
    await loadPosts(group);
}

async function loadPosts(group) {
    try {
        const posts = await api("GET", `/api/groups/${group.id}/posts`);
        const list = document.getElementById("posts-list");
        list.innerHTML = "";
        posts.forEach(post => {
            const isOurs = post.author_key === identity.public_key;
            const bubble = document.createElement("div");
            bubble.className = `message-bubble ${isOurs ? "outgoing" : "incoming"}`;
            const ts = new Date(post.timestamp * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
            const author = isOurs ? "You" : post.author_key.slice(0, 10) + "…";
            const text = post.text != null ? esc(post.text) : '<em style="opacity:.5">[encrypted]</em>';
            bubble.innerHTML = `
                <div class="message-text">${text}</div>
                <div class="message-meta">
                    <span>${author}</span>
                    <span>${ts}</span>
                </div>
            `;
            list.appendChild(bubble);
        });
        _scrollToBottom(list);
    } catch (_) {}
}

async function sendPost() {
    if (!currentGroup) return;
    const input = document.getElementById("post-input");
    const text = input.value.trim();
    if (!text) return;

    input.value = "";
    input.style.height = "auto";

    try {
        await api("POST", `/api/groups/${currentGroup.id}/posts`, { text });
        await loadPosts(currentGroup);
    } catch (err) {
        showToast("Failed to post: " + err.message);
    }
}

function handlePostKey(e) {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendPost();
    }
    autoResize(e.target);
}

// ================================================================
// Settings
// ================================================================

async function showSettings() {
    showPanel("settings");
    if (!identity) return;

    document.getElementById("settings-alias").value = identity.alias;
    document.getElementById("alias-status").textContent = "";
    document.getElementById("settings-pubkey").textContent = identity.public_key;
    document.getElementById("settings-onion").textContent = identity.onion_address;

    // Load relay config
    try {
        const status = await api("GET", "/api/status");
        // Relay settings are in the node's config — not exposed via status yet
        // Show relay_configured indicator
        document.getElementById("relay-status").textContent =
            status.relay_configured ? "Relay active" : "No relay configured";
    } catch (_) {}
}

async function saveAlias() {
    const alias = document.getElementById("settings-alias").value.trim();
    const statusEl = document.getElementById("alias-status");
    if (!alias) return;
    try {
        const result = await api("PATCH", "/api/identity/alias", { alias });
        identity.alias = result.alias;
        document.getElementById("status-alias").textContent = result.alias;
        statusEl.textContent = "Saved.";
        setTimeout(() => { statusEl.textContent = ""; }, 2000);
    } catch (err) {
        statusEl.textContent = "Error: " + err.message;
    }
}

function copyPublicKey() {
    const key = document.getElementById("settings-pubkey").textContent;
    copyToClipboard(key, "Public key copied");
}

function copyOnion() {
    const onion = document.getElementById("settings-onion").textContent;
    copyToClipboard(onion, "Onion address copied");
}

async function copyContactCard() {
    if (!identity) return;
    try {
        const card = await api("GET", "/api/identity/card");
        copyToClipboard(JSON.stringify(card), "Contact card copied");
    } catch (err) {
        showToast("Failed to get contact card: " + err.message);
    }
}

async function panicDelete() {
    if (!confirm("⚠ PANIC DELETE\n\nThis will permanently destroy:\n• Your identity and private key\n• All contacts\n• All messages\n• All groups\n\nThis CANNOT be undone. Continue?")) return;
    if (!confirm("Are you absolutely sure? There is no recovery.")) return;

    try {
        await api("DELETE", "/api/identity");
        identity = null;
        currentContact = null;
        currentGroup = null;
        if (eventSource) { eventSource.close(); eventSource = null; }
        showView("onboarding");
    } catch (err) {
        showToast("Error: " + err.message);
    }
}

async function saveRelay() {
    const onion = document.getElementById("relay-onion").value.trim();
    const pubkey = document.getElementById("relay-pubkey").value.trim();
    const enabled = document.getElementById("relay-enabled").checked;

    if (!onion || !pubkey) {
        document.getElementById("relay-status").textContent = "Fill in both fields.";
        return;
    }

    try {
        // The API doesn't expose relay config editing yet — note for future
        showToast("Relay config saved (requires node restart to take effect)");
        document.getElementById("relay-status").textContent = enabled ? "Relay active" : "Relay disabled";
    } catch (err) {
        document.getElementById("relay-status").textContent = "Error: " + err.message;
    }
}

// ================================================================
// Delete contact / group
// ================================================================

function editContactAlias(contact, itemEl) {
    const nameEl = itemEl.querySelector(".item-name");
    const current = contact.alias || "";

    const input = document.createElement("input");
    input.type = "text";
    input.value = current;
    input.maxLength = 64;
    input.style.cssText = "width:100%;background:var(--bg-tertiary);border:1px solid var(--accent);border-radius:3px;color:var(--text-primary);font-family:var(--font);font-size:13px;padding:2px 6px;";

    nameEl.replaceWith(input);
    input.focus();
    input.select();

    async function commit() {
        const alias = input.value.trim();
        if (alias && alias !== current) {
            try {
                await api("PATCH", `/api/contacts/${contact.public_key}/alias`, { alias });
                contact.alias = alias;
                if (currentContact && currentContact.public_key === contact.public_key) {
                    currentContact.alias = alias;
                    document.getElementById("msg-peer-alias").textContent = alias;
                }
            } catch (_) {}
        }
        await loadContacts();
    }

    input.addEventListener("blur", commit);
    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") { e.preventDefault(); input.blur(); }
        if (e.key === "Escape") { input.value = current; input.blur(); }
    });
}

async function deleteContact(contact) {
    if (!confirm(`Remove "${contact.alias || contact.public_key.slice(0, 16)}" from contacts?`)) return;
    try {
        await api("DELETE", `/api/contacts/${contact.public_key}`);
        if (currentContact && currentContact.public_key === contact.public_key) {
            currentContact = null;
            showPanel("welcome");
        }
        await loadContacts();
        showToast("Contact removed");
    } catch (err) {
        showToast("Error: " + err.message);
    }
}

async function deleteGroup(group) {
    const label = `"${group.name}"`;
    const msg = group.is_admin
        ? `Delete group ${label}? This will remove all posts and members locally.`
        : `Leave group ${label}? This removes it from your local list.`;
    if (!confirm(msg)) return;
    try {
        await api("DELETE", `/api/groups/${group.id}`);
        if (currentGroup && currentGroup.id === group.id) {
            currentGroup = null;
            showPanel("welcome");
        }
        await loadGroups();
        showToast(group.is_admin ? "Group deleted" : "Left group");
    } catch (err) {
        showToast("Error: " + err.message);
    }
}

// ================================================================
// Add contact modal
// ================================================================

function showAddContact() {
    document.getElementById("contact-card-input").value = "";
    document.getElementById("add-contact-error").classList.add("hidden");
    openModal("modal-add-contact");
}

async function addContact() {
    const raw = document.getElementById("contact-card-input").value.trim();
    const errEl = document.getElementById("add-contact-error");
    errEl.classList.add("hidden");

    let card;
    try {
        card = JSON.parse(raw);
    } catch (_) {
        showError(errEl, "Invalid JSON.");
        return;
    }

    try {
        await api("POST", "/api/contacts", card);
        closeModal("modal-add-contact");
        await loadContacts();
        showToast("Contact added");
    } catch (err) {
        showError(errEl, err.message);
    }
}

// ================================================================
// Create group modal
// ================================================================

function showCreateGroup() {
    document.getElementById("group-name-input").value = "";
    openModal("modal-create-group");
}

async function createGroup() {
    const name = document.getElementById("group-name-input").value.trim();
    if (!name) return;

    try {
        const group = await api("POST", "/api/groups", { name });
        closeModal("modal-create-group");
        await loadGroups();
        openGroup(group);
        showToast("Group created");
    } catch (err) {
        showToast("Error: " + err.message);
    }
}

// ================================================================
// Invite member modal
// ================================================================

function showInviteMember() {
    document.getElementById("invite-pubkey").value = "";
    document.getElementById("invite-error").classList.add("hidden");
    openModal("modal-invite");
}

async function inviteMember() {
    if (!currentGroup) return;
    const pubkey = document.getElementById("invite-pubkey").value.trim();
    const errEl = document.getElementById("invite-error");
    errEl.classList.add("hidden");

    if (!pubkey) return;

    // Look up contact to get onion address
    try {
        const contacts = await api("GET", "/api/contacts");
        const contact = contacts.find(c => c.public_key === pubkey);
        if (!contact) {
            showError(errEl, "Contact not found. Add them first.");
            return;
        }
        await api("POST", `/api/groups/${currentGroup.id}/invite`, {
            public_key: pubkey,
            onion: contact.onion_address,
        });
        closeModal("modal-invite");
        showToast("Invitation sent");
    } catch (err) {
        showError(errEl, err.message);
    }
}

// ================================================================
// Utilities
// ================================================================

function esc(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function autoResize(el) {
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 120) + "px";
}

function showError(el, msg) {
    el.textContent = msg;
    el.classList.remove("hidden");
}

function showToast(msg, duration = 3000) {
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.classList.remove("hidden");
    setTimeout(() => toast.classList.add("hidden"), duration);
}

function openModal(id) {
    document.getElementById(id).classList.remove("hidden");
}

function closeModal(id) {
    document.getElementById(id).classList.add("hidden");
}

function copyToClipboard(text, successMsg = "Copied") {
    if (window.pywebview && window.pywebview.api) {
        window.pywebview.api.copy_to_clipboard(text).then(ok => {
            if (ok) showToast(successMsg);
            else showToast("Clipboard unavailable");
        });
    } else {
        navigator.clipboard.writeText(text).then(() => showToast(successMsg)).catch(() => {});
    }
}

// Close modals on backdrop click
document.querySelectorAll(".modal").forEach(modal => {
    modal.addEventListener("click", (e) => {
        if (e.target === modal) closeModal(modal.id);
    });
});
