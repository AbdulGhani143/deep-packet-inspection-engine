// DPI Engine Visual Console - Client Application Logic

document.addEventListener("DOMContentLoaded", () => {
    // State
    let currentPackets = [];
    let currentFilter = "all";
    let searchQuery = "";
    let selectedPacket = null;
    let packetPage = 0;
    const pageSize = 100;

    // Elements
    const runBtn = document.getElementById("runBtn");
    const regenBtn = document.getElementById("regenBtn");
    const runningIndicator = document.getElementById("runningIndicator");
    const engineStatusBadge = document.getElementById("engineStatusBadge");
    
    const modeInputs = document.querySelectorAll("input[name='capture-mode']");
    const liveControls = document.getElementById("liveControls");
    const interfaceSelect = document.getElementById("captureInterface");
    const durationSelect = document.getElementById("captureDuration");
    const captureBtn = document.getElementById("captureBtn");
    const captureReady = document.getElementById("captureReady");
    const enforceBlock = document.getElementById("enforceBlock");
    const clearBlocksBtn = document.getElementById("clearBlocksBtn");
    const enforcementBadge = document.getElementById("enforcementBadge");
    const enforcementMessage = document.getElementById("enforcementMessage");
    const requestMessage = document.getElementById("requestMessage");
    let busy = false;
    let liveReady = false;
    let statusKnown = false;
    const mode = () => document.querySelector("input[name='capture-mode']:checked").value;

    function message(text, error = false) {
        requestMessage.hidden = !text;
        requestMessage.textContent = text;
        requestMessage.classList.toggle("error", error);
    }

    function updateControls() {
        const live = mode() === "live";
        liveControls.hidden = !live;
        document.getElementById("captureTarget").textContent = live ? "live_capture.pcap" : "test_dpi.pcap";
        runBtn.querySelector("span").textContent = live ? "RE-INSPECT CAPTURED TRAFFIC" : "EXECUTE C++ INSPECTION";
        runBtn.disabled = busy || (live && (!statusKnown || !liveReady));
        regenBtn.hidden = live;
        captureReady.textContent = liveReady ? "Saved live capture available for re-inspection." : "Capture new live traffic before re-inspecting.";
        document.querySelectorAll(".control-panel input, .control-panel select, .control-panel button, .btn-preset").forEach(el => {
            if (el !== runBtn) el.disabled = busy;
        });
        runningIndicator.style.display = busy ? "flex" : "none";
    }

    function showEnforcement(status) {
        if (!status || typeof status !== "object") {
            enforcementBadge.textContent = "OS BLOCKING STATUS UNKNOWN";
            enforcementBadge.className = "enforcement-badge warning";
            enforcementMessage.textContent = "The server did not confirm OS blocking or cleanup.";
            return;
        }
        const warnings = Array.isArray(status.warnings) ? status.warnings : [];
        const active = status.success === true && status.enabled === true;
        const cleared = status.success === true && status.enabled === false;
        enforcementBadge.textContent = active ? "ACTIVE (BLOCKING BROWSER TRAFFIC)" : cleared ? "SIMULATION ONLY" : "OS BLOCKING UNCONFIRMED";
        enforcementBadge.className = "enforcement-badge" + (active ? " active" : cleared ? "" : " warning");
        enforcementMessage.textContent = warnings.length ? warnings.join(" · ") : active ? "OS rules applied. Hosts entries cover exact domain names." : cleared ? "OS blocks cleared. Inspections use simulation only." : "Some rules may remain active. Clear OS blocks to retry cleanup.";
    }

    async function clearOsBlocks() {
        if (busy) return;
        busy = true;
        updateControls();
        message("Clearing OS blocks…");
        try {
            const res = await fetch("/api/clear_blocks", { method: "POST" });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || "OS cleanup request failed");
            showEnforcement(data.enforcement_status);
            if (data.success === false || data.enforcement_status?.success !== true) {
                message("OS cleanup could not be confirmed. See the blocking status above.", true);
            } else {
                enforceBlock.checked = false;
                message("OS blocks cleared.");
            }
        } catch (err) {
            showEnforcement(null);
            message(err.message, true);
        } finally {
            busy = false;
            updateControls();
        }
    }
    modeInputs.forEach(input => input.addEventListener("change", updateControls));
    clearBlocksBtn.addEventListener("click", clearOsBlocks);
    enforceBlock.addEventListener("change", () => {
        if (!enforceBlock.checked) clearOsBlocks();
        else message("OS blocking will be requested with your next inspection.");
    });
    captureBtn.addEventListener("click", () => runInspection(true));
    updateControls();

    // Metrics
    const metricTotal = document.getElementById("metricTotal");
    const metricBytes = document.getElementById("metricBytes");
    const metricForwarded = document.getElementById("metricForwarded");
    const metricForwardedPct = document.getElementById("metricForwardedPct");
    const metricDropped = document.getElementById("metricDropped");
    const metricDroppedPct = document.getElementById("metricDroppedPct");
    const metricProtocols = document.getElementById("metricProtocols");
    
    // Panels
    const appList = document.getElementById("appList");
    const threadStats = document.getElementById("threadStats");
    const packetTableBody = document.getElementById("packetTableBody");
    const packetCountBadge = document.getElementById("packetCountBadge");
    const packetSearch = document.getElementById("packetSearch");
    const filterButtons = document.querySelectorAll(".btn-filter");
    
    // Packet Detail Drawer
    const packetDetailPanel = document.getElementById("packetDetailPanel");
    const detailTitle = document.getElementById("detailTitle");
    const detailContent = document.getElementById("detailContent");
    const closeDetailBtn = document.getElementById("closeDetailBtn");

    // Inputs
    const blockIpInput = document.getElementById("blockIpInput");
    const blockDomainInput = document.getElementById("blockDomainInput");
    const numLbsSelect = document.getElementById("numLbs");
    const fpsPerLbSelect = document.getElementById("fpsPerLb");

    // ==============================================================
    // Navigation Tabs
    // ==============================================================
    const navTabs = document.querySelectorAll(".nav-tab");
    navTabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const targetTab = tab.getAttribute("data-tab");
            navTabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            
            document.querySelectorAll(".tab-content").forEach(content => {
                content.classList.remove("active");
            });
            const contentEl = document.getElementById(`tab-${targetTab}`);
            if (contentEl) contentEl.classList.add("active");
        });
    });

    // ==============================================================
    // Check Engine Status
    // ==============================================================
    async function checkStatus() {
        try {
            const res = await fetch("/api/status");
            const data = await res.json();
            if (!res.ok) throw new Error("Status request failed");
            statusKnown = true;
            liveReady = data.live_pcap_ready === true;
            document.getElementById("rootHint").hidden = data.is_root !== false;
            const selected = interfaceSelect.value;
            interfaceSelect.replaceChildren(new Option("AUTO / ACTIVE INTERFACE", "auto"));
            if (Array.isArray(data.interfaces)) {
                [...new Set(data.interfaces)].filter(name => typeof name === "string" && name !== "auto").forEach(name => interfaceSelect.add(new Option(name, name)));
            }
            if ([...interfaceSelect.options].some(o => o.value === selected)) interfaceSelect.value = selected;
            updateControls();
            if (data.engine_ready) {
                engineStatusBadge.textContent = "● " + (data.system ? data.system.toUpperCase() + " READY" : "C++ ENGINE READY");
                engineStatusBadge.style.color = "var(--status-green)";
            } else {
                engineStatusBadge.textContent = "● BINARY NOT FOUND";
                engineStatusBadge.style.color = "var(--status-amber)";
            }
        } catch (e) {
            engineStatusBadge.textContent = "● BRIDGE DISCONNECTED";
            engineStatusBadge.style.color = "var(--status-red)";
        }
    }
    checkStatus();

    // ==============================================================
    // Demo Presets
    // ==============================================================
    const presetButtons = document.querySelectorAll(".btn-preset");
    presetButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            presetButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            
            const preset = btn.getAttribute("data-preset");
            if (!busy) applyPreset(preset);
        });
    });

    function applyPreset(preset) {
        document.querySelectorAll("input[name='block-app']").forEach(cb => cb.checked = false);
        blockIpInput.value = "";
        blockDomainInput.value = "";

        if (preset === "baseline") {
            // No blocks
        } else if (preset === "social") {
            setAppCheckbox("YouTube", true);
            setAppCheckbox("Facebook", true);
        } else if (preset === "ip") {
            blockIpInput.value = "192.168.1.50";
        } else if (preset === "strict") {
            setAppCheckbox("YouTube", true);
            setAppCheckbox("Facebook", true);
            setAppCheckbox("TikTok", true);
            blockIpInput.value = "192.168.1.50";
        } else if (preset === "all") {
            document.querySelectorAll("input[name='block-app']").forEach(cb => cb.checked = true);
        }

        message("Preset applied. Inspecting the selected saved capture…");
        runInspection();
    }

    function setAppCheckbox(val, checked) {
        const cb = document.querySelector(`input[name='block-app'][value='${val}']`);
        if (cb) cb.checked = checked;
    }

    // ==============================================================
    // Execute Inspection (POST /api/inspect)
    // ==============================================================
    async function runInspection(captureNew = false) {
        if (busy) return;
        captureNew = captureNew === true;
        if (mode() === "live" && !captureNew && !liveReady) {
            message("Capture new live traffic first.", true);
            return;
        }
        busy = true;
        updateControls();
        message(captureNew ? `Capturing live traffic for ${durationSelect.value}s, then inspecting…` : "Inspecting captured traffic…");

        const blocked_apps = Array.from(document.querySelectorAll("input[name='block-app']:checked"))
                                  .map(cb => cb.value);
        const blocked_ips = blockIpInput.value.trim() ? [blockIpInput.value.trim()] : [];
        const blocked_domains = blockDomainInput.value.trim() ? [blockDomainInput.value.trim()] : [];
        const num_lbs = parseInt(numLbsSelect.value, 10) || 2;
        const fps_per_lb = parseInt(fpsPerLbSelect.value, 10) || 2;

        try {
            const response = await fetch("/api/inspect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    blocked_apps,
                    blocked_ips,
                    blocked_domains,
                    num_lbs,
                    fps_per_lb,
                    mode: mode(),
                    capture_new: mode() === "live" && captureNew,
                    interface: interfaceSelect.value,
                    duration: parseInt(durationSelect.value, 10),
                    enforce_block: enforceBlock.checked
                })
            });
            const data = await response.json();
            showEnforcement(data.enforcement_status);
            if (!response.ok || data.success === false || !data.stats || !Array.isArray(data.packets)) {
                throw new Error(data.error || data.stderr || "Inspection failed; previous results retained.");
            }
            const ruleCount = blocked_apps.length + blocked_ips.length + blocked_domains.length;
            document.getElementById("resultContext").textContent =
                `Last result: ${mode() === "live" ? "live_capture.pcap" : "test_dpi.pcap"} · ${captureNew ? "new live capture" : "saved capture inspection"} · ${ruleCount} selected rule(s) · OS blocking ${enforceBlock.checked ? "requested (check status above)" : "not requested"}. Changing controls does not change these results until you inspect again.`;
            renderResults(data);
            message("Inspection complete.");
            if (mode() === "live" && captureNew) liveReady = true;
        } catch (err) {
            message(err.message, true);
            console.error("Error executing inspection:", err);
        } finally {
            busy = false;
            updateControls();
        }
    }

    runBtn.addEventListener("click", () => runInspection(false));

    // ==============================================================
    // Render Results
    // ==============================================================
    function renderResults(data) {
        selectedPacket = null;
        packetDetailPanel.style.display = "none";
        const stats = { ...(data.stats || {}) };
        // Older running bridges label every packet absent from output as DROP.
        // Correct only frames demonstrably outside this engine's supported path.
        let correctedLegacy = 0;
        currentPackets = (data.packets || []).map(original => {
            const pkt = { ...original };
            const hex = (pkt.hex_preview || "").replace(/\s/g, "").toLowerCase();
            const etherType = hex.slice(24, 28);
            if (pkt.protocol === "OTHER") {
                if (etherType === "0806") pkt.protocol = "ARP";
                else if (etherType === "86dd") pkt.protocol = "IPv6";
            }
            if (pkt.status === "DROP" && !["TCP", "UDP"].includes(pkt.protocol)) {
                pkt.status = "UNINSPECTED";
                pkt.reason = `Not inspected: ${pkt.protocol} is outside the IPv4 TCP/UDP inspection path, or the packet is incomplete`;
                correctedLegacy++;
            }
            return pkt;
        });
        if (correctedLegacy) {
            stats.dropped = currentPackets.filter(p => p.status === "DROP").length;
            stats.apps = {};
            currentPackets.forEach(p => { stats.apps[p.app] = (stats.apps[p.app] || 0) + 1; });
        }
        stats.uninspected = currentPackets.filter(p => p.status === "UNINSPECTED").length;
        packetPage = 0;

        const total = stats.total_packets || currentPackets.length;
        const forwarded = stats.forwarded || 0;
        const dropped = stats.dropped || 0;
        const fPct = total > 0 ? ((forwarded / total) * 100).toFixed(1) : "0.0";
        const dPct = total > 0 ? ((dropped / total) * 100).toFixed(1) : "0.0";

        metricTotal.textContent = total;
        metricBytes.textContent = (stats.total_bytes ? stats.total_bytes.toLocaleString() : "--") + " BYTES";
        metricForwarded.textContent = forwarded;
        metricForwardedPct.textContent = `${fPct}% PASSED`;
        metricDropped.textContent = dropped;
        metricDroppedPct.textContent = `${dPct}% NOT IN OUTPUT`;
        document.getElementById("metricUninspected").textContent = `Not inspected: ${stats.uninspected || 0}`;
        metricProtocols.textContent = `${stats.tcp_packets || 0} TCP / ${stats.udp_packets || 0} UDP`;

        renderAppBreakdown(stats.apps || {}, total);
        renderThreadTelemetry(stats.threads || {});
        filterAndRenderTable();
    }

    function renderAppBreakdown(apps, total) {
        const sorted = Object.entries(apps).sort((a, b) => b[1] - a[1]);
        if (sorted.length === 0) {
            appList.innerHTML = '<div class="empty-state">No applications detected</div>';
            return;
        }

        appList.innerHTML = sorted.map(([app, count]) => {
            const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
            return `
                <div class="app-row">
                    <div class="app-row-labels">
                        <span class="app-name">${escapeHtml(app)}</span>
                        <span class="app-count-pct">${count} pkts (${pct}%)</span>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill" style="width: ${Math.max(pct, 2)}%;"></div>
                    </div>
                </div>
            `;
        }).join("");
    }

    function renderThreadTelemetry(threads) {
        const lbs = threads.lbs || {};
        const fps = threads.fps || {};

        let html = '<div class="thread-group-title">Load Balancers (Hashing)</div>';
        if (Object.keys(lbs).length > 0) {
            html += Object.entries(lbs).map(([name, count]) => `
                <div class="thread-row">
                    <span>${name}</span>
                    <strong>${count} dispatched</strong>
                </div>
            `).join("");
        } else {
            html += '<div class="thread-row"><span>LB Threads</span><strong>Not reported</strong></div>';
        }

        html += '<div class="thread-group-title" style="margin-top: 8px;">Fast Path Workers</div>';
        if (Object.keys(fps).length > 0) {
            html += Object.entries(fps).map(([name, count]) => `
                <div class="thread-row">
                    <span>${name}</span>
                    <strong>${count} processed</strong>
                </div>
            `).join("");
        } else {
            html += '<div class="thread-row"><span>FP Workers</span><strong>Not reported</strong></div>';
        }

        threadStats.innerHTML = html;
    }

    // ==============================================================
    // Table Filtering & Search
    // ==============================================================
    function selectPacketFilter(filter, clearSearch = false) {
        currentFilter = filter;
        packetPage = 0;
        if (clearSearch) {
            searchQuery = "";
            packetSearch.value = "";
        }
        filterButtons.forEach(btn => {
            const active = btn.getAttribute("data-filter") === filter;
            btn.classList.toggle("active", active);
            btn.setAttribute("aria-pressed", String(active));
        });
        filterAndRenderTable();
    }
    filterButtons.forEach(btn => btn.addEventListener("click", () => selectPacketFilter(btn.getAttribute("data-filter"))));
    document.querySelectorAll("[data-packet-filter]").forEach(btn => btn.addEventListener("click", () => {
        selectPacketFilter(btn.dataset.packetFilter, true);
        document.querySelector(".table-filters").scrollIntoView({ block: "center", behavior: "smooth" });
        document.querySelector(".btn-filter.active").focus({ preventScroll: true });
    }));
    document.getElementById("resetPacketFilters").addEventListener("click", () => selectPacketFilter("all", true));
    document.getElementById("prevPackets").addEventListener("click", () => { packetPage--; filterAndRenderTable(); });
    document.getElementById("nextPackets").addEventListener("click", () => { packetPage++; filterAndRenderTable(); });
    packetSearch.addEventListener("input", (e) => {
        searchQuery = e.target.value.toLowerCase().trim();
        packetPage = 0;
        filterAndRenderTable();
    });

    function filterAndRenderTable() {
        let filtered = currentPackets.filter(pkt => {
            if (currentFilter !== "all" && pkt.status !== currentFilter) {
                return false;
            }
            if (searchQuery) {
                const haystack = `${pkt.id} ${pkt.src_ip} ${pkt.dest_ip} ${pkt.protocol} ${pkt.app} ${pkt.domain} ${pkt.reason}`.toLowerCase();
                if (!haystack.includes(searchQuery)) {
                    return false;
                }
            }
            return true;
        });

        const pages = Math.ceil(filtered.length / pageSize);
        packetPage = Math.max(0, Math.min(packetPage, pages - 1));
        document.getElementById("prevPackets").disabled = packetPage === 0;
        document.getElementById("nextPackets").disabled = packetPage + 1 >= pages;
        document.getElementById("packetPageLabel").textContent = filtered.length ? `Page ${packetPage + 1} of ${pages} · ${pageSize} rows per page` : "No matching packets";
        filterButtons.forEach(btn => {
            const filter = btn.getAttribute("data-filter");
            const count = filter === "all" ? currentPackets.length : currentPackets.filter(p => p.status === filter).length;
            btn.textContent = `${filter === "all" ? "ALL" : filter === "FORWARD" ? "FORWARDED" : filter === "UNINSPECTED" ? "NOT INSPECTED" : "REPORTED DROPS"} (${count})`;
        });
        document.querySelector(".table-container").scrollTop = 0;
        packetCountBadge.textContent = `// ${filtered.length} OF ${currentPackets.length} PACKETS`;

        if (filtered.length === 0) {
            packetTableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="empty-table">No packets match the current filter.</td>
                </tr>
            `;
            return;
        }

        packetTableBody.innerHTML = filtered.slice(packetPage * pageSize, (packetPage + 1) * pageSize).map(pkt => {
            const isDropped = pkt.status === "DROP";
            const rowClass = isDropped ? "row-dropped" : "";
            const badgeClass = isDropped ? "drop" : pkt.status === "UNINSPECTED" ? "uninspected" : "forward";
            const badgeText = isDropped ? "REPORTED DROP" : pkt.status === "UNINSPECTED" ? "NOT INSPECTED" : "FORWARD";
            
            return `
                <tr class="${rowClass}" data-id="${pkt.id}">
                    <td><strong>#${pkt.id}</strong></td>
                    <td>${pkt.timestamp.split(".")[1] || pkt.timestamp}</td>
                    <td>${escapeHtml(pkt.src_ip)}:${pkt.src_port} → ${escapeHtml(pkt.dest_ip)}:${pkt.dest_port}</td>
                    <td><span class="proto-tag">${pkt.protocol}</span></td>
                    <td class="domain-text">${pkt.domain !== "-" ? escapeHtml(pkt.domain) : '<span style="color:var(--text-faint);">-</span>'}</td>
                    <td>${escapeHtml(pkt.app)}</td>
                    <td><span class="badge ${badgeClass}">${badgeText}</span></td>
                    <td class="reason-text">${escapeHtml(pkt.reason || "-")}</td>
                </tr>
            `;
        }).join("");

        document.querySelectorAll("#packetTableBody tr[data-id]").forEach(row => {
            row.addEventListener("click", () => {
                const id = parseInt(row.getAttribute("data-id"), 10);
                const pkt = currentPackets.find(p => p.id === id);
                if (pkt) showPacketDetail(pkt);
            });
        });
    }

    // ==============================================================
    // Packet Detail Drawer
    // ==============================================================
    function showPacketDetail(pkt) {
        selectedPacket = pkt;
        detailTitle.textContent = `PACKET #${pkt.id} // FORENSIC BREAKDOWN`;
        
        detailContent.innerHTML = `
            <div class="detail-grid">
                <div class="detail-item">
                    <span>Timestamp</span>
                    <strong>${pkt.timestamp}</strong>
                </div>
                <div class="detail-item">
                    <span>Packet Size</span>
                    <strong>${pkt.length} bytes</strong>
                </div>
                <div class="detail-item">
                    <span>Verdict</span>
                    <strong style="color: ${pkt.status === 'DROP' ? 'var(--status-red)' : pkt.status === 'UNINSPECTED' ? 'var(--text-muted)' : 'var(--status-green)'}">
                        ${pkt.status} (${escapeHtml(pkt.reason)})
                    </strong>
                </div>
                <div class="detail-item">
                    <span>Source (L3/L4)</span>
                    <strong>${escapeHtml(pkt.src_ip)}:${pkt.src_port}</strong>
                </div>
                <div class="detail-item">
                    <span>Destination (L3/L4)</span>
                    <strong>${escapeHtml(pkt.dest_ip)}:${pkt.dest_port}</strong>
                </div>
                <div class="detail-item">
                    <span>L7 Identified App / SNI</span>
                    <strong>${pkt.domain !== '-' ? escapeHtml(pkt.domain) : escapeHtml(pkt.app)}</strong>
                </div>
            </div>
            <div>
                <span style="font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); display: block; margin-bottom: 4px;">RAW PACKET HEX DUMP (FIRST 32 BYTES):</span>
                <div class="hex-box">${pkt.hex_preview || "N/A"}</div>
            </div>
        `;
        packetDetailPanel.style.display = "block";
    }

    closeDetailBtn.addEventListener("click", () => {
        packetDetailPanel.style.display = "none";
    });

    // ==============================================================
    // Regenerate Test PCAP
    // ==============================================================
    regenBtn.addEventListener("click", async () => {
        if (busy) return;
        busy = true;
        updateControls();
        regenBtn.disabled = true;
        regenBtn.textContent = "REGENERATING...";
        try {
            const res = await fetch("/api/regenerate", { method: "POST" });
            const data = await res.json();
            if (data.success) {
                busy = false;
                await runInspection();
            } else {
                alert("Failed to regenerate PCAP:\n" + data.log);
            }
        } catch (e) {
            alert("Error connecting to server: " + e.message);
        } finally {
            busy = false;
            updateControls();
            regenBtn.disabled = false;
            regenBtn.textContent = "REGENERATE PCAP ↻";
        }
    });

    function escapeHtml(str) {
        if (!str) return "";
        return str.toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            runInspection();
        }
    });

    // Inspection and OS changes start only from an explicit user action.
});
