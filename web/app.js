// ========== State ==========
let chats = {};          // id -> { id, query, status, events[], stream }
let activeChatId = null; // currently viewed chat
let chatRenderState = {};// id -> { thinkingEl, toolCard, toolArgsBuffer }
let askModalState = { open: false, chatId: null, loading: false };
let chatActivity = {};   // id -> { detail, lastEventAt, lastType, state }
let activityTicker = null;
let stallWatchState = {}; // id -> { inFlight, lastTriggeredAt, paused, timeoutStreak, lastStatusRequestText, lastStatusResultText }

const STALL_CHECK_THRESHOLD_SEC = 200;
const STALL_CHECK_COOLDOWN_SEC = 200;
const STALL_STATUS_CHECK_TIMEOUT_MS = 65000;

const ASK_FOLLOWUP_PROMPTS = {
    explain: 'Explain your previous answer in plain language for a non-technical person.',
    impact: 'Based on your previous answer, what realistic attacker impact is possible and how severe is it?',
    fix: 'Based on your previous answer, give exact remediation steps in priority order.',
};

const $ = id => document.getElementById(id);

function isAbortLikeError(err) {
    const name = String(err?.name || '').toLowerCase();
    const msg = String(err?.message || err || '').toLowerCase();
    if (name === 'aborterror') return true;
    return msg.includes('aborted') || msg.includes('aborterror') || msg.includes('signal is aborted');
}

function ensureChatActivity(chatId) {
    if (!chatActivity[chatId]) {
        chatActivity[chatId] = {
            detail: 'Starting...',
            lastEventAt: Date.now(),
            lastType: 'init',
            state: 'idle',
        };
    }
    return chatActivity[chatId];
}

function createInitialStallWatchState() {
    return {
        inFlight: false,
        lastTriggeredAt: 0,
        paused: false,
        timeoutStreak: 0,
        lastStatusRequestText: '',
        lastStatusResultText: '',
    };
}

function inferActivityFromEvent(type, data = {}) {
    if (type === 'thinking') return { detail: 'Thinking through next steps...', state: 'running' };
    if (type === 'step') return { detail: `Step ${data.iteration || '?'} / ${data.max || '?'}`, state: 'running' };
    if (type === 'tool_start' || type === 'tool_call') {
        const toolName = data.name || 'tool';
        return { detail: `Running ${toolName}...`, state: 'running' };
    }
    if (type === 'tool_result') {
        const toolName = data.name || 'tool';
        return { detail: `Analyzing ${toolName} output...`, state: 'running' };
    }
    if (type === 'vuln_scan_progress') {
        if (data.current_path) return { detail: `Scanning: ${data.current_path}`, state: 'running' };
        return { detail: 'Scanning exposed paths...', state: 'running' };
    }
    if (type === 'nuclei_progress') return { detail: `Nuclei running (${data.findings_so_far || 0} findings)...`, state: 'running' };
    if (type === 'terminal_progress') return { detail: `Running command (${data.elapsed || 0}s)...`, state: 'running' };
    if (type.endsWith('_progress')) return { detail: data.message || 'Working...', state: 'running' };
    if (type.endsWith('_start')) return { detail: data.message || 'Starting task...', state: 'running' };
    if (type === 'final_report') return { detail: 'Composing final report...', state: 'running' };
    if (type === 'final_truth_report') return { detail: 'Verifying final truth...', state: 'running' };
    if (type === 'ask_question') return { detail: 'Answering your follow-up...', state: 'running' };
    if (type === 'ask_answer') return { detail: 'Follow-up answered', state: 'done' };
    if (type === 'status_check') return { detail: 'No updates for 200s. Asking AI for a status check...', state: 'running' };
    if (type === 'status_check_result') {
        if (data.paused) {
            return { detail: 'Auto-check paused after repeated timeouts; run still active.', state: 'running' };
        }
        return { detail: 'AI posted a status check update', state: 'running' };
    }
    if (type === 'recovery') {
        const detail = data.message || 'Recovering after interruption...';
        return { detail, state: 'running' };
    }
    if (type === 'severe_path') {
        if (data.state === 'confirmed') return { detail: 'Severe-path impact confirmed', state: 'running' };
        if (data.state === 'blocked') return { detail: 'Severe-path checks blocked', state: 'running' };
        return { detail: 'Running severe-path verification...', state: 'running' };
    }
    if (type === 'coverage_degraded') {
        return { detail: 'Coverage degraded; fallback active', state: 'running' };
    }
    if (type === 'error') return { detail: data.message ? `Error: ${data.message}` : 'Error encountered', state: 'error' };
    if (type === 'done') return { detail: 'Completed', state: 'done' };
    return { detail: '', state: 'running' };
}

function recordChatActivity(chatId, type, data = {}) {
    const activity = ensureChatActivity(chatId);
    const inf = inferActivityFromEvent(type, data);
    activity.lastEventAt = Date.now();
    activity.lastType = type;
    if (inf.detail) activity.detail = inf.detail;
    if (inf.state) activity.state = inf.state;
}

function renderActiveChatActivity() {
    const badge = $('chatActivityBadge');
    if (!badge) return;

    if (!activeChatId || !chats[activeChatId]) {
        badge.className = 'activity-badge idle flex-shrink-0';
        badge.textContent = 'Idle';
        badge.title = 'No active chat selected';
        return;
    }

    const chat = chats[activeChatId];
    const activity = ensureChatActivity(activeChatId);
    const ageSec = Math.max(0, Math.floor((Date.now() - activity.lastEventAt) / 1000));

    let cls = 'idle';
    let text = activity.detail || 'Idle';

    if (chat.status === 'running') {
        if (ageSec >= 20) {
            cls = 'stalled';
            text = `Still running • no update ${ageSec}s`;
        } else {
            cls = 'running';
            if (ageSec >= 6) {
                text = `${activity.detail || 'Working...'} • ${ageSec}s ago`;
            } else {
                text = activity.detail || 'Working...';
            }
        }
    } else if (chat.status === 'done') {
        if (activity.state === 'error') {
            cls = 'error';
            if (!text) text = 'Stopped after connection error';
        } else {
            cls = 'done';
            if (!text || text.includes('running')) text = 'Completed';
        }
    } else if (chat.status === 'error') {
        cls = 'error';
        if (!text) text = 'Error';
    }

    badge.className = `activity-badge ${cls} flex-shrink-0`;
    badge.textContent = text;
    badge.title = `Status: ${chat.status || 'unknown'} | Last update: ${ageSec}s ago`;
}

function startActivityTicker() {
    if (activityTicker) return;
    activityTicker = setInterval(() => {
        runStallWatchdog();
        renderActiveChatActivity();
    }, 1000);
}

// ========== API ==========

async function apiCreateChat(query, mode = 'auto', verificationPolicy = 'balanced') {
    const resp = await fetch('/api/chats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, mode, verification_policy: verificationPolicy }),
    });
    return resp.json();
}

async function apiListChats() {
    const resp = await fetch('/api/chats');
    return resp.json();
}

async function apiGetChat(id) {
    const resp = await fetch(`/api/chats/${id}`);
    return resp.json();
}

async function apiDeleteChat(id) {
    await fetch(`/api/chats/${id}`, { method: 'DELETE' });
}

async function apiStopChat(id) {
    const resp = await fetch(`/api/chats/${id}/stop`, { method: 'POST' });
    return resp.json();
}

async function apiStatusCheck(id, question) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort('status-check-timeout'), STALL_STATUS_CHECK_TIMEOUT_MS);
    try {
        const resp = await fetch(`/api/chats/${id}/status_check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question }),
            signal: controller.signal,
        });
        let data = {};
        try {
            data = await resp.json();
        } catch (e) {
            data = {};
        }
        if (!resp.ok) {
            const msg = data?.error || `HTTP ${resp.status}`;
            throw new Error(msg);
        }
        return { ...data, timed_out: false };
    } catch (err) {
        if (isAbortLikeError(err)) {
            return { timed_out: true };
        }
        throw err;
    } finally {
        clearTimeout(timeout);
    }
}

async function apiVerifyTruth(id) {
    const resp = await fetch(`/api/chats/${id}/verify_truth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
    });
    return resp.json();
}

async function apiAskInChat(id, question) {
    const resp = await fetch(`/api/chats/${id}/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question }),
    });
    return resp.json();
}

// ========== Chat management ==========

async function startChat(query, mode = 'auto') {
    if (!query || !query.trim()) return;
    const normalizedMode = ['ask', 'deep', 'auto'].includes(mode) ? mode : 'deep';
    const data = await apiCreateChat(query.trim(), normalizedMode, 'balanced');
    chats[data.id] = { ...data, events: [] };
    chatActivity[data.id] = {
        detail: normalizedMode === 'deep' ? 'Starting deep scan...' : 'Starting...',
        lastEventAt: Date.now(),
        lastType: 'create',
        state: 'running',
    };
    chatRenderState[data.id] = { thinkingEl: null, toolCard: null, toolArgsBuffer: {} };
    stallWatchState[data.id] = createInitialStallWatchState();
    renderChatList();
    selectChat(data.id);
    streamChat(data.id);
}

function getStallWatchState(chatId) {
    if (!stallWatchState[chatId]) {
        stallWatchState[chatId] = createInitialStallWatchState();
    } else {
        const w = stallWatchState[chatId];
        if (typeof w.paused !== 'boolean') w.paused = false;
        if (typeof w.timeoutStreak !== 'number') w.timeoutStreak = 0;
        if (typeof w.lastStatusRequestText !== 'string') w.lastStatusRequestText = '';
        if (typeof w.lastStatusResultText !== 'string') w.lastStatusResultText = '';
    }
    return stallWatchState[chatId];
}

async function triggerStallStatusCheck(chatId) {
    const chat = chats[chatId];
    if (!chat || chat.status !== 'running') return;

    const watch = getStallWatchState(chatId);
    if (watch.paused) return;
    if (watch.inFlight) return;
    watch.inFlight = true;
    watch.lastTriggeredAt = Date.now();

    const activity = ensureChatActivity(chatId);
    activity.detail = 'No updates for 200s. Asking AI to check status...';
    activity.state = 'running';
    activity.lastEventAt = Date.now();
    if (activeChatId === chatId) renderActiveChatActivity();

    const question = (
        "No progress events have appeared for over 200 seconds. "
        + "Check what is likely happening now, identify likely blocker, and give immediate next action."
    );

    try {
        const data = await apiStatusCheck(chatId, question);
        if (typeof data?.timeout_streak === 'number') {
            watch.timeoutStreak = Math.max(0, data.timeout_streak);
        }
        if (typeof data?.paused === 'boolean') {
            watch.paused = data.paused;
        }
        if (data?.timed_out) {
            watch.timeoutStreak = Math.max(0, (watch.timeoutStreak || 0) + 1);
            const stalledActivity = ensureChatActivity(chatId);
            if (watch.timeoutStreak >= 3) {
                watch.paused = true;
                stalledActivity.detail = 'Auto-check paused after repeated timeouts; run still active.';
            } else {
                stalledActivity.detail = 'Status check timed out; will retry after cooldown if still stalled.';
            }
            stalledActivity.state = 'running';
            stalledActivity.lastEventAt = Date.now();
            if (activeChatId === chatId) renderActiveChatActivity();
            return;
        }
        if (data?.paused) {
            watch.paused = true;
            const stalledActivity = ensureChatActivity(chatId);
            stalledActivity.detail = 'Auto-check paused after repeated timeouts; run still active.';
            stalledActivity.state = 'running';
            stalledActivity.lastEventAt = Date.now();
            if (activeChatId === chatId) renderActiveChatActivity();
            return;
        }
        if (data?.error) {
            throw new Error(data.error);
        }
        if (data?.skipped) {
            const stalledActivity = ensureChatActivity(chatId);
            stalledActivity.detail = `Status check skipped (${data.status || 'not running'}).`;
            stalledActivity.state = 'running';
            stalledActivity.lastEventAt = Date.now();
            if (activeChatId === chatId) renderActiveChatActivity();
        }
    } catch (err) {
        const msg = `Auto status check failed: ${String(err?.message || err || 'Unknown error')}`;
        console.warn(msg);
        const stalledActivity = ensureChatActivity(chatId);
        stalledActivity.detail = 'Auto status check failed; still monitoring for progress updates.';
        stalledActivity.state = 'running';
        stalledActivity.lastEventAt = Date.now();
        if (activeChatId === chatId) renderActiveChatActivity();
    } finally {
        watch.inFlight = false;
    }
}

function runStallWatchdog() {
    const now = Date.now();
    for (const chatId of Object.keys(chats)) {
        const chat = chats[chatId];
        if (!chat || chat.status !== 'running') continue;

        const activity = ensureChatActivity(chatId);
        const ageSec = Math.max(0, Math.floor((now - activity.lastEventAt) / 1000));
        if (ageSec < STALL_CHECK_THRESHOLD_SEC) continue;

        const watch = getStallWatchState(chatId);
        const cooloffMs = STALL_CHECK_COOLDOWN_SEC * 1000;
        if (watch.inFlight) continue;
        if (watch.paused) continue;
        if (watch.lastTriggeredAt && (now - watch.lastTriggeredAt) < cooloffMs) continue;

        triggerStallStatusCheck(chatId);
    }
}

function streamChat(chatId) {
    const evtSource = new EventSource(`/api/chats/${chatId}/stream`);
    if (chats[chatId]) chats[chatId]._evtSource = evtSource;

    const handleMsg = (e) => {
        try {
            const data = JSON.parse(e.data);
            const watch = getStallWatchState(chatId);
            if (e.type === 'status_check_result') {
                if (typeof data?.timeout_streak === 'number') watch.timeoutStreak = Math.max(0, data.timeout_streak);
                if (typeof data?.paused === 'boolean') watch.paused = data.paused;
            } else if (e.type !== 'status_check') {
                watch.timeoutStreak = 0;
                watch.paused = false;
                watch.lastStatusRequestText = '';
                watch.lastStatusResultText = '';
            }
            if (!chats[chatId]) chats[chatId] = { id: chatId, events: [], status: 'running' };
            chats[chatId].events.push({ type: e.type, ...data });
            recordChatActivity(chatId, e.type, data);

            // If this is the active chat, render it live
            if (activeChatId === chatId) {
                handleEventForChat(chatId, e.type, data);
            }

            // Update sidebar status
            if (e.type === 'step') {
                updateChatListItem(chatId);
            }
        } catch (err) {}
    };

    ['step', 'thinking', 'thinking_done', 'tool_start', 'tool_args',
     'tool_call', 'tool_result', 'final_report', 'final_truth_report', 'error',
     'status_check', 'status_check_result', 'recovery', 'severe_path', 'coverage_degraded',
     'terminal_start', 'terminal_output', 'terminal_progress', 
     'terminal_done', 'terminal_timeout', 'terminal_error',
     'vuln_scan_start', 'vuln_scan_progress', 'vuln_scan_done',
     'ffuf_start', 'ffuf_output', 'ffuf_progress', 'ffuf_done', 'tool_info',
     'tool_progress', 'tool_output',
     'nuclei_start', 'nuclei_info', 'nuclei_stats', 'nuclei_finding',
     'nuclei_output', 'nuclei_progress', 'nuclei_done',
     'exploit_start', 'exploit_progress', 'exploit_done'].forEach(evt => {
        evtSource.addEventListener(evt, handleMsg);
    });

    // Handle done separately to close stream and notify
    evtSource.addEventListener('done', (e) => {
        let doneData = {};
        try {
            const data = JSON.parse(e.data);
            doneData = data;
            if (!chats[chatId]) chats[chatId] = { id: chatId, events: [], status: 'running' };
            chats[chatId].events.push({ type: 'done', ...data });
            if (activeChatId === chatId) {
                handleEventForChat(chatId, 'done', data);
            }
        } catch (err) {}

        recordChatActivity(chatId, 'done', doneData);
        evtSource.close();
        if (chats[chatId]) chats[chatId]._evtSource = null;
        if (chats[chatId]) chats[chatId].status = 'done';
        renderChatList();
        // Notify if not the active chat
        if (activeChatId !== chatId) {
            showToast('success', 'Scan Complete', chats[chatId]?.query || chatId);
            playNotifSound();
        }
        if (activeChatId === chatId) {
            setChatHeaderStatus('done');
        }
        updateStopChatButton();
    });

    evtSource.addEventListener('error', (e) => {
        evtSource.close();
        if (chats[chatId]) chats[chatId]._evtSource = null;
        recordChatActivity(chatId, 'error', { message: 'Stream connection lost' });
        if (chats[chatId] && chats[chatId].status === 'running') {
            chats[chatId].status = 'done';
            renderChatList();
        }
        renderActiveChatActivity();
        updateStopChatButton();
    });
}

async function selectChat(chatId) {
    if (askModalState.open && askModalState.chatId !== chatId) {
        closeAskModal();
    }
    activeChatId = chatId;
    renderChatList();

    // Show chat view
    $('emptyState').classList.add('hidden');
    $('chatView').classList.remove('hidden');

    const chat = chats[chatId];
    // Fetch full events from server if we don't have them yet
    if (!chat || !chat.events || chat.events.length === 0) {
        const data = await apiGetChat(chatId);
        if (data.error) return;
        chats[chatId] = { ...chats[chatId], ...data };
        chatRenderState[chatId] = { thinkingEl: null, toolCard: null, toolArgsBuffer: {} };
    }

    // Clear and re-render all events
    renderChatFull(chatId);
    if (askModalState.open && askModalState.chatId === chatId) {
        renderAskModalHistory(chatId);
    }
    renderActiveChatActivity();
    updateStopChatButton();
}

async function deleteChat(chatId, e) {
    e.stopPropagation();
    await apiDeleteChat(chatId);
    // Close SSE if running
    if (chats[chatId]?._evtSource) {
        chats[chatId]._evtSource.close();
    }
    delete chats[chatId];
    delete chatActivity[chatId];
    delete chatRenderState[chatId];
    delete stallWatchState[chatId];
    if (activeChatId === chatId) {
        activeChatId = null;
        closeAskModal();
        $('emptyState').classList.remove('hidden');
        $('chatView').classList.add('hidden');
    }
    renderChatList();
    renderActiveChatActivity();
    updateStopChatButton();
}

async function stopActiveChat() {
    const chatId = activeChatId;
    if (!chatId || !chats[chatId] || chats[chatId].status !== 'running') return;

    const btn = $('stopChatBtn');
    if (btn && btn.dataset.loading === '1') return;
    if (btn) {
        btn.dataset.loading = '1';
        updateStopChatButton();
    }

    try {
        await apiStopChat(chatId);
        if (chats[chatId]?._evtSource) {
            chats[chatId]._evtSource.close();
            chats[chatId]._evtSource = null;
        }

        const latest = await apiGetChat(chatId);
        if (!latest?.error) {
            chats[chatId] = { ...chats[chatId], ...latest };
        } else {
            chats[chatId].status = 'done';
        }

        if (activeChatId === chatId) {
            renderChatFull(chatId);
        } else {
            renderChatList();
        }
        showToast('success', 'Prompt Stopped', chats[chatId]?.query || chatId);
    } catch (err) {
        showToast('error', 'Stop Failed', String(err?.message || err || 'Unable to stop this run'));
    } finally {
        if (btn) btn.dataset.loading = '0';
        updateStopChatButton();
    }
}

// ========== Rendering: Chat list ==========

function renderChatList() {
    const list = $('chatList');
    const ids = Object.keys(chats).sort((a, b) => {
        const ca = chats[a].created_at || '';
        const cb = chats[b].created_at || '';
        return cb.localeCompare(ca);
    });

    list.innerHTML = ids.map(id => {
        const c = chats[id];
        const isActive = id === activeChatId;
        const dotClass = c.status === 'running' ? 'running' : (c.status === 'error' ? 'error' : 'done');
        const time = formatTime(c.created_at);
        const label = c.query || 'Untitled';
        return `
            <div class="chat-item ${isActive ? 'active' : ''}" onclick="selectChat('${id}')">
                <div class="chat-dot ${dotClass}"></div>
                <div class="chat-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
                <span class="chat-time">${time}</span>
                <button class="chat-delete" onclick="deleteChat('${id}', event)" title="Delete">&times;</button>
            </div>
        `;
    }).join('');
}

function updateChatListItem(chatId) {
    // Light update — just refresh status dot
    const items = document.querySelectorAll('.chat-item');
    // Full re-render is cheap enough
    renderChatList();
}

// ========== Rendering: Chat content ==========

function renderChatFull(chatId) {
    const chat = chats[chatId];
    if (!chat) return;
    ensureChatActivity(chatId);
    const watch = getStallWatchState(chatId);
    watch.lastStatusRequestText = '';
    watch.lastStatusResultText = '';

    // Set header
    $('chatTitle').textContent = chat.query || 'Untitled';
    setChatHeaderStatus(chat.status);

    // Clear output
    const output = $('outputArea');
    output.innerHTML = '';
    $('finalReport').classList.add('hidden');
    $('reportContent').innerHTML = '';
    clearTruthPanel();
    const verifyBtn = $('verifyTruthBtn');
    verifyBtn.classList.add('hidden');
    verifyBtn.disabled = false;
    verifyBtn.textContent = 'Find Final Truth';
    verifyBtn.dataset.running = '0';

    // Reset render state
    chatRenderState[chatId] = { thinkingEl: null, toolCard: null, toolArgsBuffer: {} };

    // Replay all events
    for (const ev of (chat.events || [])) {
        handleEventForChat(chatId, ev.type, ev);
    }
    if ((chat.events || []).length === 0) {
        if (chat.status === 'running') {
            chatActivity[chatId].detail = chat.recovery_state === 'recovering'
                ? 'Recovering after interruption...'
                : 'Starting task...';
            chatActivity[chatId].state = 'running';
        } else if (chat.status === 'done') {
            chatActivity[chatId].detail = 'Completed';
            chatActivity[chatId].state = 'done';
        } else {
            chatActivity[chatId].detail = 'Idle';
            chatActivity[chatId].state = 'idle';
        }
    }
    renderActiveChatActivity();
    updateStopChatButton();

    // Backward compatibility: old scans may not have `final_report`.
    ensureLegacyFinalTruthUI(chatId);
}

function setChatHeaderStatus(status) {
    const dot = $('chatStatusDot');
    if (status === 'running') {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-cyber-green animate-pulse flex-shrink-0';
    } else if (status === 'done') {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-accent-500 flex-shrink-0';
    } else {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-gray-500 flex-shrink-0';
    }
    renderActiveChatActivity();
    updateStopChatButton();
}

function updateStopChatButton() {
    const btn = $('stopChatBtn');
    if (!btn) return;

    const chat = activeChatId ? chats[activeChatId] : null;
    const running = !!chat && chat.status === 'running';
    const loading = btn.dataset.loading === '1';

    btn.classList.toggle('hidden', !running && !loading);
    btn.disabled = !running || loading;
    btn.textContent = loading ? 'Stopping...' : 'Stop';
    btn.title = running ? 'Stop current prompt' : 'No running prompt';
}

function handleEventForChat(chatId, type, data) {
    const output = $('outputArea');
    const rs = chatRenderState[chatId];
    if (!rs) return;
    recordChatActivity(chatId, type, data);

    switch (type) {
        case 'step':
            addStepDivider(output, data.iteration, data.max);
            $('chatStepBadge').textContent = `Step ${data.iteration}/${data.max}`;
            break;
        case 'thinking':
            appendThinking(output, rs, data.text);
            break;
        case 'thinking_done':
            endThinking(rs);
            break;
        case 'tool_start':
            endThinking(rs);
            rs.toolArgsBuffer[data.index] = '';
            break;
        case 'tool_args':
            rs.toolArgsBuffer[data.index] = (rs.toolArgsBuffer[data.index] || '') + data.text;
            break;
        case 'tool_call':
            addToolCall(output, rs, data.name, data.args, data.id);
            break;
        case 'terminal_start':
            updateTerminalProgress(data.tool_id, 'running', data.command, 0, data.timeout);
            break;
        case 'terminal_output':
            appendTerminalOutput(data.tool_id, data.text);
            break;
        case 'terminal_progress':
            updateTerminalProgress(data.tool_id, 'running', null, data.elapsed, data.timeout, data.remaining);
            break;
        case 'terminal_done':
            updateTerminalProgress(data.tool_id, 'done', null, data.elapsed);
            break;
        case 'terminal_timeout':
            updateTerminalProgress(data.tool_id, 'timeout', null, data.elapsed);
            break;
        case 'terminal_error':
            updateTerminalProgress(data.tool_id, 'error', null, 0, 0, 0, data.error);
            break;
        case 'vuln_scan_start':
            updateVulnScanProgress(data.tool_id, 'start', data.target, 0, 0);
            break;
        case 'vuln_scan_progress':
            updateVulnScanProgress(data.tool_id, 'progress', null, data.tested, data.total, data.current_path);
            break;
        case 'vuln_scan_done':
            updateVulnScanProgress(data.tool_id, 'done', null, data.tested, 0, null, data.findings);
            break;
        case 'ffuf_start':
            updateToolStreamProgress(data.tool_id, 'start', `🔍 Fuzzing ${escapeHtml(data.target || '')} [${data.mode}] — wordlist: ${data.wordlist || 'builtin'}`);
            break;
        case 'ffuf_output':
            appendToolStreamLine(data.tool_id, data.text);
            break;
        case 'ffuf_progress':
            updateToolStreamProgress(data.tool_id, 'progress', `🔍 Fuzzing... ${data.elapsed}s / ${data.timeout}s`);
            break;
        case 'ffuf_done':
            updateToolStreamProgress(data.tool_id, 'done', `✓ Fuzzing complete in ${data.elapsed}s — ${data.found} results found`);
            break;
        case 'tool_info':
            updateToolStreamProgress(data.tool_id, 'info', `ℹ️ ${data.message}`);
            break;
        case 'tool_progress': {
            const msg = data.message || `Running... ${data.elapsed || 0}s / ${data.timeout || 0}s`;
            updateToolStreamProgress(data.tool_id, 'progress', msg);
            break;
        }
        case 'tool_output':
            appendToolStreamLine(data.tool_id, data.text || '');
            break;
        case 'nuclei_start':
            updateToolStreamProgress(data.tool_id, 'start', `🧬 Nuclei scanning ${escapeHtml(data.target || '')} [${data.templates}] severity: ${data.severity}`);
            break;
        case 'nuclei_info':
        case 'nuclei_stats':
            updateToolStreamProgress(data.tool_id, 'info', data.message);
            break;
        case 'nuclei_finding': {
            const sevColors = {critical:'🔴',high:'🟠',medium:'🟡',low:'🔵',info:'⚪'};
            const icon = sevColors[data.severity] || '❓';
            appendToolStreamLine(data.tool_id, `${icon} [${(data.severity||'').toUpperCase()}] ${data.name} — ${data.matched_at}\n`);
            break;
        }
        case 'nuclei_output':
            appendToolStreamLine(data.tool_id, data.text + '\n');
            break;
        case 'nuclei_progress':
            updateToolStreamProgress(data.tool_id, 'progress', `🧬 Scanning... ${data.elapsed}s / ${data.timeout}s — ${data.findings_so_far} findings so far`);
            break;
        case 'nuclei_done':
            updateToolStreamProgress(data.tool_id, 'done', `✓ Nuclei complete in ${data.elapsed}s — ${data.total_findings} vulnerabilities found`);
            break;
        case 'exploit_start':
            updateToolStreamProgress(data.tool_id, 'start', `💀 Exploiting ${escapeHtml(data.target || '')} [${data.type || 'auto'}]`);
            break;
        case 'exploit_progress':
            appendToolStreamLine(data.tool_id, data.message + '\n');
            break;
        case 'exploit_done':
            updateToolStreamProgress(data.tool_id, 'done', `✓ Exploitation complete`);
            break;
        case 'tool_result':
            addToolResult(output, rs, data.name, data.result, data.id);
            break;
        case 'final_report':
            if (chats[chatId]) chats[chatId].finalReport = data.text || '';
            showFinalReport(chatId, data.text || '');
            break;
        case 'final_truth_report':
            if (chats[chatId]) {
                chats[chatId].truthReport = data.markdown || '';
                chats[chatId].truthSummary = data.summary || null;
                chats[chatId].truthFindings = data.findings || [];
            }
            $('finalReport').classList.remove('hidden');
            $('verifyTruthBtn').classList.remove('hidden');
            renderTruthPanel(data.markdown || '', data.summary || null, data.findings || []);
            break;
        case 'ask_question':
            addAskQuestion(output, data.text || '');
            if (askModalState.open && askModalState.chatId === chatId) {
                renderAskModalHistory(chatId);
            }
            break;
        case 'ask_answer':
            addAskAnswer(output, data.text || '');
            if (askModalState.open && askModalState.chatId === chatId) {
                renderAskModalHistory(chatId);
            }
            break;
        case 'status_check':
            {
                const watch = getStallWatchState(chatId);
                const text = data.text || 'No updates for 200s. Requesting AI status check.';
                if (watch.lastStatusRequestText === text) break;
                watch.lastStatusRequestText = text;
                addStatusCheckRequest(output, text);
            }
            break;
        case 'status_check_result': {
            const watch = getStallWatchState(chatId);
            const text = data.text || '(No status update generated)';
            if (watch.lastStatusResultText === text) break;
            watch.lastStatusResultText = text;
            addStatusCheckResult(output, text);
            break;
        }
        case 'recovery':
            addStatusCheckResult(output, data.message || 'Recovered run and resumed from persisted state.');
            break;
        case 'severe_path':
            addStatusCheckResult(output, data.message || `Severe-path status: ${data.state || 'unknown'}`);
            break;
        case 'coverage_degraded':
            addStatusCheckResult(output, data.message || 'Coverage degraded; fallback enabled.');
            break;
        case 'error':
            showErrorCard(output, data.message);
            if (askModalState.open && askModalState.chatId === chatId) {
                setAskModalError(data.message || 'Unknown error');
            }
            break;
        case 'done':
            if (chats[chatId]) chats[chatId].status = 'done';
            setChatHeaderStatus('done');
            renderChatList();
            break;
    }
    if (activeChatId === chatId) {
        renderActiveChatActivity();
    }
}

// ========== UI building blocks ==========

function addStepDivider(container, iteration, max) {
    const div = document.createElement('div');
    div.className = 'step-divider fade-in';
    div.innerHTML = `<span class="step-badge">Step ${iteration} / ${max}</span>`;
    container.appendChild(div);
}

function appendThinking(container, rs, text) {
    if (!rs.thinkingEl) {
        // Collapse previous
        container.querySelectorAll('.thinking-body').forEach(el => el.classList.add('collapsed'));
        const card = document.createElement('div');
        card.className = 'thinking-card fade-in';
        card.innerHTML = `
            <div class="thinking-header">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
                </svg>
                Thinking...
            </div>
            <div class="thinking-body streaming-cursor"></div>
        `;
        container.appendChild(card);
        rs.thinkingEl = card.querySelector('.thinking-body');
    }
    rs.thinkingEl.textContent += text;
    rs.thinkingEl.scrollTop = rs.thinkingEl.scrollHeight;
    scrollOutput();
}

function endThinking(rs) {
    if (rs.thinkingEl) {
        rs.thinkingEl.classList.remove('streaming-cursor');
        rs.thinkingEl = null;
    }
}

function addToolCall(container, rs, name, args, id) {
    endThinking(rs);
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args, null, 2);
    const card = document.createElement('div');
    card.className = 'tool-card fade-in';
    card.id = `tool-${id}`;
    card.innerHTML = `
        <div class="tool-header">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
            </svg>
            <span class="tool-name">${escapeHtml(name)}</span>
            <span class="tool-status running">running</span>
        </div>
        <div class="tool-args">${escapeHtml(argsStr)}</div>
        <div class="tool-result" style="display:none;"></div>
    `;
    container.appendChild(card);
    rs.toolCard = card;
    scrollOutput();
}

function addToolResult(container, rs, name, result, id) {
    const card = document.getElementById(`tool-${id}`) || rs.toolCard;
    if (card) {
        const statusEl = card.querySelector('.tool-status');
        statusEl.className = 'tool-status done';
        statusEl.textContent = 'done';
        const resultEl = card.querySelector('.tool-result');
        resultEl.style.display = 'block';
        let displayResult = result;
        if (result.length > 3000) {
            displayResult = result.substring(0, 3000) + `\n\n... (${result.length - 3000} more chars)`;
        }
        resultEl.textContent = displayResult;
    }
    scrollOutput();
}

function addAskQuestion(container, text) {
    const card = document.createElement('div');
    card.className = 'ask-question-card fade-in';
    card.innerHTML = `
        <div class="ask-label">You asked</div>
        <div class="ask-body">${escapeHtml(text || '')}</div>
    `;
    container.appendChild(card);
    scrollOutput();
}

function addAskAnswer(container, text) {
    const card = document.createElement('div');
    card.className = 'ask-answer-card fade-in';
    card.innerHTML = `
        <div class="ask-label">Answer</div>
        <div class="ask-answer-body"></div>
    `;
    container.appendChild(card);
    const body = card.querySelector('.ask-answer-body');
    const htmlContent = marked.parse(text || '', { breaks: true, gfm: true });
    body.innerHTML = htmlContent;
    body.querySelectorAll('a').forEach(a => {
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
    });
    scrollOutput();
}

function addStatusCheckRequest(container, text) {
    const card = document.createElement('div');
    card.className = 'ask-question-card fade-in';
    card.innerHTML = `
        <div class="ask-label">Auto Check</div>
        <div class="ask-body">${escapeHtml(text || '')}</div>
    `;
    container.appendChild(card);
    scrollOutput();
}

function addStatusCheckResult(container, text) {
    const card = document.createElement('div');
    card.className = 'ask-answer-card fade-in';
    card.innerHTML = `
        <div class="ask-label">AI Status Update</div>
        <div class="ask-answer-body"></div>
    `;
    container.appendChild(card);
    const body = card.querySelector('.ask-answer-body');
    const htmlContent = marked.parse(text || '', { breaks: true, gfm: true });
    body.innerHTML = htmlContent;
    body.querySelectorAll('a').forEach(a => {
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
    });
    scrollOutput();
}

function setTruthBadge(state, text) {
    const badge = $('truthBadge');
    if (!text) {
        badge.className = 'truth-badge hidden';
        badge.textContent = '';
        return;
    }
    badge.className = `truth-badge ${state || ''}`;
    badge.textContent = text;
}

function clearTruthPanel() {
    $('truthPanel').classList.add('hidden');
    $('truthContent').innerHTML = '';
    setTruthBadge('', '');
}

function buildTruthGateHtml(summary, findings) {
    const arr = Array.isArray(findings) ? findings : [];
    const verified = arr.filter(f =>
        f?.status === 'confirmed'
        && ['critical', 'high'].includes((f?.severity || '').toLowerCase())
        && (f?.direct_impact || f?.bounty_ready)
    );
    const actionable = arr.filter(f =>
        !verified.includes(f)
        && ['confirmed', 'partial'].includes((f?.status || '').toLowerCase())
        && Number(f?.evidence_count || ((f?.evidence || []).length || 0)) > 0
    );
    const unverified = arr.filter(f => !verified.includes(f));

    const lines = [];
    lines.push('<div class="mb-4 p-3 rounded-xl border border-sky-400/25 bg-sky-500/10">');
    lines.push('<div class="text-xs uppercase tracking-wide text-sky-300 font-semibold mb-2">Severity Gate</div>');
    if (verified.length > 0) {
        lines.push('<div class="text-sm text-emerald-300 font-semibold">Exploit-Proven HIGH/CRITICAL</div>');
        lines.push('<ul class="mt-2 text-sm text-gray-200 list-disc pl-5">');
        for (const f of verified) {
            const sev = escapeHtml((f?.severity || '').toUpperCase());
            const name = escapeHtml(f?.name || 'Finding');
            lines.push(`<li><strong>[${sev}] ${name}</strong> (${escapeHtml(String(f?.confidence || 0))}% confidence)</li>`);
        }
        lines.push('</ul>');
    } else {
        lines.push('<div class="text-sm text-amber-300 font-semibold">No exploit-proven HIGH/CRITICAL findings yet.</div>');
    }
    if (actionable.length > 0) {
        lines.push(`<div class="mt-2 text-sm text-cyan-300 font-semibold">Actionable evidence-backed findings: ${actionable.length}</div>`);
    } else {
        lines.push('<div class="mt-2 text-sm text-gray-300 font-semibold">Actionable evidence-backed findings: 0</div>');
    }
    lines.push(`<div class="mt-2 text-xs text-gray-400">Unverified / needs manual proof: ${unverified.length}</div>`);
    lines.push('</div>');
    return lines.join('');
}

function renderTruthPanel(markdown, summary, findings) {
    if (!markdown) return;
    $('truthPanel').classList.remove('hidden');
    const gateHtml = buildTruthGateHtml(summary, findings);
    const htmlContent = marked.parse(markdown, { breaks: true, gfm: true });
    $('truthContent').innerHTML = gateHtml + htmlContent;
    $('truthContent').querySelectorAll('a').forEach(a => {
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
    });
    const ready = summary?.ready_count;
    const total = summary?.total_findings;
    if (typeof ready === 'number' && typeof total === 'number') {
        setTruthBadge('done', `Ready ${ready}/${total}`);
    } else {
        setTruthBadge('done', 'Verified');
    }
    scrollOutput();
}

function showFinalReport(chatId, text) {
    $('finalReport').classList.remove('hidden');
    $('finalReport').classList.add('fade-in');
    const htmlContent = marked.parse(text, { breaks: true, gfm: true });
    $('reportContent').innerHTML = htmlContent;
    $('reportContent').querySelectorAll('a').forEach(a => {
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
    });
    const verifyBtn = $('verifyTruthBtn');
    verifyBtn.classList.remove('hidden');
    verifyBtn.disabled = false;
    verifyBtn.textContent = 'Find Final Truth';
    verifyBtn.dataset.running = '0';

    const chat = chats[chatId];
    if (chat && chat.truthReport) {
        renderTruthPanel(chat.truthReport, chat.truthSummary, chat.truthFindings || []);
    } else {
        clearTruthPanel();
    }

    scrollOutput();
}

function findLegacyReportText(chat) {
    if (!chat || !chat.events) return '';

    for (let i = chat.events.length - 1; i >= 0; i--) {
        const ev = chat.events[i];
        if (ev.type === 'final_report' && ev.text) return ev.text;
    }
    for (let i = chat.events.length - 1; i >= 0; i--) {
        const ev = chat.events[i];
        if (ev.type === 'thinking_done' && ev.text && ev.text.length > 160) return ev.text;
    }
    return '';
}

function ensureLegacyFinalTruthUI(chatId) {
    const chat = chats[chatId];
    if (!chat || chat.status === 'running') return;

    const verifyBtn = $('verifyTruthBtn');
    if (!verifyBtn.classList.contains('hidden')) return;

    const legacyReport = findLegacyReportText(chat);
    if (legacyReport) {
        showFinalReport(chatId, legacyReport);
        return;
    }

    const hasAnyUsefulData = (chat.events || []).some(ev =>
        (ev.type === 'tool_result' && ev.result) || (ev.type === 'thinking_done' && ev.text)
    );
    if (!hasAnyUsefulData) return;

    $('finalReport').classList.remove('hidden');
    $('finalReport').classList.add('fade-in');
    $('reportContent').innerHTML = `
        <p class="text-gray-400">
            Legacy scan loaded. A structured final report wasn't saved in this chat, but you can still run
            <strong>Find Final Truth</strong> using stored tool outputs.
        </p>
    `;
    verifyBtn.classList.remove('hidden');
    verifyBtn.disabled = false;
    verifyBtn.textContent = 'Find Final Truth';
    verifyBtn.dataset.running = '0';
}

async function runFinalTruthCheck() {
    const chatId = activeChatId;
    if (!chatId || !chats[chatId]) return;

    const btn = $('verifyTruthBtn');
    if (btn.dataset.running === '1') return;

    btn.dataset.running = '1';
    btn.disabled = true;
    btn.textContent = 'Verifying...';
    setTruthBadge('running', 'Verifying');

    try {
        const data = await apiVerifyTruth(chatId);
        if (data.error) {
            throw new Error(data.error);
        }
        chats[chatId].truthReport = data.markdown || '';
        chats[chatId].truthSummary = data.summary || null;
        chats[chatId].truthFindings = data.findings || [];
        renderTruthPanel(chats[chatId].truthReport, chats[chatId].truthSummary, chats[chatId].truthFindings);
        showToast('success', 'Final Truth Complete', chats[chatId]?.query || chatId);
    } catch (err) {
        setTruthBadge('error', 'Verification failed');
        showToast('error', 'Final Truth Failed', String(err?.message || err || 'Unknown error'));
    } finally {
        btn.dataset.running = '0';
        btn.disabled = false;
        btn.textContent = 'Find Final Truth';
    }
}

window.runFinalTruthCheck = runFinalTruthCheck;

async function askInCurrentChat(chatId, question) {
    const chat = chats[chatId];
    if (!chat) return '';
    if (chat.status === 'running') {
        showToast('error', 'Chat Busy', 'Wait for the current run to finish');
        throw new Error('Chat is currently running');
    }

    const q = (question || '').trim();
    if (!q) return '';

    const askEvent = { type: 'ask_question', text: q };
    chat.events.push(askEvent);
    recordChatActivity(chatId, 'ask_question', askEvent);
    if (activeChatId === chatId) {
        handleEventForChat(chatId, 'ask_question', askEvent);
    }

    chat.status = 'running';
    setChatHeaderStatus('running');
    renderChatList();

    try {
        const data = await apiAskInChat(chatId, q);
        if (data.error) throw new Error(data.error);

        const answerEvent = { type: 'ask_answer', text: data.answer || '(No answer generated)' };
        chat.events.push(answerEvent);
        recordChatActivity(chatId, 'ask_answer', answerEvent);
        if (activeChatId === chatId) {
            handleEventForChat(chatId, 'ask_answer', answerEvent);
        }
        return answerEvent.text;
    } catch (err) {
        const msg = String(err?.message || err || 'Unknown error');
        chat.events.push({ type: 'error', message: msg });
        recordChatActivity(chatId, 'error', { message: msg });
        if (activeChatId === chatId) {
            handleEventForChat(chatId, 'error', { message: msg });
        }
        throw new Error(msg);
    } finally {
        chat.status = 'done';
        recordChatActivity(chatId, 'done', {});
        setChatHeaderStatus('done');
        renderChatList();
        renderActiveChatActivity();
    }
}

function setAskModalLoading(isLoading) {
    askModalState.loading = !!isLoading;
    const input = $('askModalInput');
    const send = $('askModalSendBtn');
    input.disabled = !!isLoading;
    send.disabled = !!isLoading;
    send.textContent = isLoading ? 'Asking...' : 'Ask';
    document.querySelectorAll('.ask-action-chip').forEach(btn => {
        btn.disabled = !!isLoading;
    });
}

function setAskModalError(message) {
    const el = $('askModalError');
    const msg = (message || '').trim();
    if (!msg) {
        el.classList.add('hidden');
        el.textContent = '';
        return;
    }
    el.classList.remove('hidden');
    el.textContent = msg;
}

function closeAskModal() {
    $('askModal').classList.add('hidden');
    $('askModal').setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
    askModalState.open = false;
    askModalState.chatId = null;
    setAskModalError('');
    setAskModalLoading(false);
}

function getAskEvents(chatId) {
    return (chats[chatId]?.events || []).filter(ev => ev.type === 'ask_question' || ev.type === 'ask_answer');
}

function renderAskModalHistory(chatId) {
    const container = $('askModalHistory');
    if (!container) return;
    const events = getAskEvents(chatId);
    container.innerHTML = '';
    if (!events.length) {
        const empty = document.createElement('div');
        empty.className = 'ask-modal-empty';
        empty.textContent = 'No follow-up questions yet. Ask for plain-language explanation, real-world impact, or exact remediation steps.';
        container.appendChild(empty);
        return;
    }

    for (const ev of events) {
        const item = document.createElement('div');
        item.className = `ask-modal-item ${ev.type === 'ask_question' ? 'question' : 'answer'} fade-in`;

        const label = document.createElement('div');
        label.className = 'ask-modal-item-label';
        label.textContent = ev.type === 'ask_question' ? 'You asked' : 'Answer';
        item.appendChild(label);

        const body = document.createElement('div');
        body.className = 'ask-modal-item-body';
        if (ev.type === 'ask_answer') {
            body.innerHTML = marked.parse(ev.text || '', { breaks: true, gfm: true });
            body.querySelectorAll('a').forEach(a => {
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
            });
        } else {
            body.textContent = ev.text || '';
        }
        item.appendChild(body);

        if (ev.type === 'ask_answer') {
            const actions = document.createElement('div');
            actions.className = 'ask-modal-actions';
            const chips = [
                ['explain', 'Explain'],
                ['impact', 'Impact'],
                ['fix', 'Fix'],
            ];
            for (const [action, labelText] of chips) {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'ask-action-chip';
                btn.textContent = labelText;
                btn.disabled = askModalState.loading;
                btn.addEventListener('click', () => {
                    submitAskFromModal(ASK_FOLLOWUP_PROMPTS[action] || '');
                });
                actions.appendChild(btn);
            }
            item.appendChild(actions);
        }

        container.appendChild(item);
    }
    container.scrollTop = container.scrollHeight;
}

function openAskModal(chatId, prefill = '') {
    if (!chatId || !chats[chatId]) {
        showToast('error', 'Ask Needs Context', 'Open/select a chat to ask follow-up questions');
        return;
    }
    askModalState.open = true;
    askModalState.chatId = chatId;
    $('askModal').classList.remove('hidden');
    $('askModal').setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    $('askModalTitle').textContent = `Ask Follow-up • ${chats[chatId]?.query || 'Current Chat'}`;
    $('askModalInput').value = (prefill || '').trim();
    setAskModalError('');
    setAskModalLoading(false);
    renderAskModalHistory(chatId);
    setTimeout(() => $('askModalInput').focus(), 30);
}

async function submitAskFromModal(text) {
    if (!askModalState.open || !askModalState.chatId) return;
    const q = (text || $('askModalInput').value || '').trim();
    if (!q || askModalState.loading) return;

    setAskModalError('');
    setAskModalLoading(true);
    $('askModalInput').value = '';
    try {
        await askInCurrentChat(askModalState.chatId, q);
        renderAskModalHistory(askModalState.chatId);
    } catch (err) {
        setAskModalError(String(err?.message || err || 'Unknown error'));
    } finally {
        setAskModalLoading(false);
        $('askModalInput').focus();
    }
}

function showErrorCard(container, message) {
    const card = document.createElement('div');
    card.className = 'error-card fade-in';
    card.innerHTML = `
        <div class="flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
            <strong>Error</strong>
        </div>
        <p class="mt-1">${escapeHtml(message)}</p>
    `;
    container.appendChild(card);
    scrollOutput();
}

// ========== Terminal streaming ==========

// Generic tool stream progress (used by ffuf, nuclei, etc.)
function updateToolStreamProgress(toolId, status, message) {
    const card = document.getElementById(`tool-${toolId}`);
    if (!card) return;

    const statusEl = card.querySelector('.tool-status');
    const resultEl = card.querySelector('.tool-result');

    if (status === 'start' || status === 'info') {
        if (status === 'start') {
            statusEl.className = 'tool-status running';
            statusEl.textContent = 'scanning';
        }
        resultEl.style.display = 'block';
        let progressEl = card.querySelector('.tool-stream-progress');
        if (!progressEl) {
            resultEl.innerHTML = `<div class="tool-stream-progress"></div><pre class="terminal-output" style="margin-top:0.4rem"></pre>`;
            progressEl = card.querySelector('.tool-stream-progress');
        }
        progressEl.textContent = message;
    } else if (status === 'progress') {
        const progressEl = card.querySelector('.tool-stream-progress');
        if (progressEl) progressEl.textContent = message;
    } else if (status === 'done') {
        statusEl.className = 'tool-status done';
        statusEl.textContent = 'done';
        const progressEl = card.querySelector('.tool-stream-progress');
        if (progressEl) progressEl.textContent = message;
    }
    scrollOutput();
}

function appendToolStreamLine(toolId, text) {
    const card = document.getElementById(`tool-${toolId}`);
    if (!card) return;

    const resultEl = card.querySelector('.tool-result');
    if (resultEl) resultEl.style.display = 'block';

    let outputEl = card.querySelector('.terminal-output');
    if (!outputEl) {
        resultEl.innerHTML = `<div class="tool-stream-progress"></div><pre class="terminal-output" style="margin-top:0.4rem"></pre>`;
        outputEl = card.querySelector('.terminal-output');
    }
    outputEl.textContent += text;
    outputEl.scrollTop = outputEl.scrollHeight;
    scrollOutput();
}

function updateVulnScanProgress(toolId, status, target, tested, total, currentPath, findings) {
    const card = document.getElementById(`tool-${toolId}`);
    if (!card) return;

    const statusEl = card.querySelector('.tool-status');
    const resultEl = card.querySelector('.tool-result');

    if (status === 'start') {
        statusEl.className = 'tool-status running';
        statusEl.textContent = 'scanning';
        resultEl.style.display = 'block';
        resultEl.innerHTML = `<div class="vuln-scan-progress">🔍 Starting scan of ${escapeHtml(target)}...</div>`;
    } else if (status === 'progress') {
        const progressEl = card.querySelector('.vuln-scan-progress');
        if (progressEl) {
            const percent = total > 0 ? Math.round((tested / total) * 100) : 0;
            progressEl.innerHTML = `🔍 Scanning... ${tested}/${total} paths (${percent}%)<br><span style="font-size:0.7rem;color:#6b7280;">Testing: ${escapeHtml(currentPath || '')}</span>`;
        }
    } else if (status === 'done') {
        statusEl.className = 'tool-status done';
        statusEl.textContent = 'done';
        const progressEl = card.querySelector('.vuln-scan-progress');
        if (progressEl) {
            progressEl.textContent = `✓ Scan complete - ${tested} paths tested, ${findings || 0} findings`;
        }
    }
    scrollOutput();
}

function updateTerminalProgress(toolId, status, command, elapsed, timeout, remaining, error) {
    const card = document.getElementById(`tool-${toolId}`);
    if (!card) return;

    const statusEl = card.querySelector('.tool-status');
    const resultEl = card.querySelector('.tool-result');

    if (status === 'running') {
        if (command) {
            // Initial start
            statusEl.className = 'tool-status running';
            statusEl.textContent = 'running';
            resultEl.style.display = 'block';
            resultEl.innerHTML = `<div class="terminal-progress">⏱️ Running... 0.0s / ${timeout}s</div><pre class="terminal-output"></pre>`;
        } else if (elapsed !== undefined) {
            // Progress update
            const progressEl = card.querySelector('.terminal-progress');
            if (progressEl) {
                const percent = Math.min(100, (elapsed / timeout) * 100);
                progressEl.textContent = `⏱️ Running... ${elapsed}s / ${timeout}s (${remaining}s remaining)`;
            }
        }
    } else if (status === 'done') {
        statusEl.className = 'tool-status done';
        statusEl.textContent = 'done';
        const progressEl = card.querySelector('.terminal-progress');
        if (progressEl) {
            progressEl.textContent = `✓ Completed in ${elapsed}s`;
        }
    } else if (status === 'timeout') {
        statusEl.className = 'tool-status running';
        statusEl.textContent = 'timeout';
        const progressEl = card.querySelector('.terminal-progress');
        if (progressEl) {
            progressEl.textContent = `⏱️ Timeout after ${elapsed}s`;
        }
    } else if (status === 'error') {
        statusEl.className = 'tool-status running';
        statusEl.textContent = 'error';
        if (resultEl) {
            resultEl.style.display = 'block';
            resultEl.textContent = `Error: ${error}`;
        }
    }
    scrollOutput();
}

function appendTerminalOutput(toolId, text) {
    const card = document.getElementById(`tool-${toolId}`);
    if (!card) return;

    let outputEl = card.querySelector('.terminal-output');
    if (!outputEl) {
        const resultEl = card.querySelector('.tool-result');
        if (resultEl) {
            resultEl.style.display = 'block';
            resultEl.innerHTML = `<div class="terminal-progress">⏱️ Running...</div><pre class="terminal-output"></pre>`;
            outputEl = card.querySelector('.terminal-output');
        }
    }

    if (outputEl) {
        outputEl.textContent += text;
        // Auto-scroll the terminal output itself
        outputEl.scrollTop = outputEl.scrollHeight;
    }
    scrollOutput();
}

// ========== Notifications ==========

function showToast(type, title, subtitle) {
    const container = $('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-dot"></div>
        <div class="toast-text">
            ${escapeHtml(title)}
            <strong>${escapeHtml(subtitle || '')}</strong>
        </div>
    `;
    toast.onclick = () => {
        // Find chat by query
        const chatId = Object.keys(chats).find(id => chats[id].query === subtitle);
        if (chatId) selectChat(chatId);
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 300);
    };
    container.appendChild(toast);
    // Auto-remove after 8s
    setTimeout(() => {
        if (toast.parentNode) {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }
    }, 8000);
}

function playNotifSound() {
    try {
        const audio = $('notifSound');
        // Use Web Audio API for a nice chime since base64 audio may not work
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
        osc.frequency.setValueAtTime(783.99, ctx.currentTime + 0.15); // G5
        gain.gain.setValueAtTime(0.3, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.4);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.4);
    } catch (e) {}
}

// ========== Helpers ==========

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function scrollOutput() {
    const el = $('chatOutput');
    if (!el) return;
    
    // Only auto-scroll if user is already near the bottom (within 100px)
    const isNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
    if (isNearBottom) {
        el.scrollTop = el.scrollHeight;
    }
}

function formatTime(iso) {
    if (!iso) return '';
    try {
        const d = new Date(iso);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) {
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
        return '';
    }
}

// ========== Init & event listeners ==========

async function init() {
    startActivityTicker();
    // Load chat history from server
    const serverChats = await apiListChats();
    for (const c of serverChats) {
        if (!chats[c.id]) {
            chats[c.id] = { ...c, events: [] };
            chatRenderState[c.id] = { thinkingEl: null, toolCard: null, toolArgsBuffer: {} };
            stallWatchState[c.id] = createInitialStallWatchState();
            chatActivity[c.id] = {
                detail: c.status === 'running' ? 'Resuming...' : (c.status === 'done' ? 'Completed' : 'Idle'),
                lastEventAt: Date.now(),
                lastType: 'init',
                state: c.status === 'running' ? 'running' : (c.status === 'done' ? 'done' : 'idle'),
            };
        }
        // Re-attach SSE for running chats
        if (c.status === 'running') {
            streamChat(c.id);
        }
    }
    renderChatList();

    // Auto-select the most recent chat if any
    if (serverChats.length > 0) {
        selectChat(serverChats[0].id);
    } else {
        renderActiveChatActivity();
        updateStopChatButton();
    }
}

// Empty state form
$('inputFormEmpty').addEventListener('submit', (e) => {
    e.preventDefault();
    const query = $('taskInputEmpty').value.trim();
    if (!query) return;
    const submitter = e.submitter || document.activeElement;
    const mode = submitter?.dataset?.mode || 'deep';
    $('taskInputEmpty').value = '';
    startChat(query, mode);
});

// Chat view bottom bar form
$('inputFormChat').addEventListener('submit', (e) => {
    e.preventDefault();
    const query = $('taskInputChat').value.trim();
    if (!query) return;
    const submitter = e.submitter || document.activeElement;
    const mode = submitter?.dataset?.mode || 'deep';
    $('taskInputChat').value = '';
    startChat(query, mode);
});

$('openAskModalBtn').addEventListener('click', () => {
    const prefill = $('taskInputChat').value.trim();
    $('taskInputChat').value = '';
    openAskModal(activeChatId, prefill);
});
$('stopChatBtn').addEventListener('click', stopActiveChat);

$('closeAskModalBtn').addEventListener('click', closeAskModal);
$('askModal').addEventListener('click', (e) => {
    if (e.target?.dataset?.closeAskModal === '1') {
        closeAskModal();
    }
});
$('askModalForm').addEventListener('submit', (e) => {
    e.preventDefault();
    submitAskFromModal();
});

// New chat button in sidebar
$('newChatBtn').addEventListener('click', () => {
    activeChatId = null;
    closeAskModal();
    $('emptyState').classList.remove('hidden');
    $('chatView').classList.add('hidden');
    renderChatList();
    renderActiveChatActivity();
    updateStopChatButton();
    setTimeout(() => $('taskInputEmpty').focus(), 100);
});

// Keyboard shortcut: / to focus input
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && askModalState.open) {
        closeAskModal();
        return;
    }
    if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        if (activeChatId) {
            $('taskInputChat').focus();
        } else {
            $('taskInputEmpty').focus();
        }
    }
    // Ctrl/Cmd + N for new chat
    if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
        e.preventDefault();
        $('newChatBtn').click();
    }
});

// Boot
init();
