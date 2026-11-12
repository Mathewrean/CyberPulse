/**
 * CyberPulse Client-Side Application
 * Manages reactive UI, Spotify theme switching, process monitoring,
 * tool checklist state, and incident scenario analysis.
 */

// Global State
let currentTab = "dashboard";
let allTools = [];
let currentCategory = "all";
let filterFavoritesOnly = false;
let monitorInterval = null;
let uptimeSeconds = 0;

// Presets for Scenario Advisor
const PRESETS = {
  ad: "We identified an alert showing suspicious Kerberos service ticket requests (TGS) for SPNs across domain controllers, with attempts to dump NTLM hashes from memory.",
  web: "A bug bounty submission reports SQL injection and authentication bypass on our user checkout API endpoint (/api/v2/order/pay). Need to verify impact and extract database schema.",
  c2: "A SOC alert shows endpoint 192.168.10.45 communicating with an external Russian IP on port 443 with beaconing intervals every 60 seconds. Need to extract TLS SNI and C2 traffic.",
  wifi: "Penetration test on corporate guest WiFi. Need to capture WPA2 4-way handshake or clientless PMKID and audit the pre-shared key against common enterprise wordlists.",
  privesc: "Obtained a low-privilege www-data reverse shell on an internal Linux server. Need to identify writable SUID binaries, misconfigured sudoers rules, or kernel exploits to escalate to root.",
  forensics: "An employee laptop was encrypted by ransomware with a note demanding cryptocurrency. Need to analyze volatile memory dump and disk image to find injected DLLs and decryptor keys."
};

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  setupNavigation();
  setupSearchAndFilters();
  setupAdvisor();
  setupManual();
  setupHealth();
  setupTimeline();
  setupPalette();
  setupWorkflows();
  loadData();
  startLiveMonitor();
  setInterval(updateUptimeTimer, 1000);
});

// 1. Theme Management (Spotify Dark / Light)
function initTheme() {
  const savedTheme = localStorage.getItem("cyberpulse_theme") || "dark";
  setTheme(savedTheme);

  document.getElementById("theme-toggle").addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    setTheme(next);
  });
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("cyberpulse_theme", theme);
  const icon = document.getElementById("theme-icon");
  if (theme === "light") {
    icon.innerHTML = '<path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>';
  } else {
    icon.innerHTML = '<path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/>';
  }
}

// 2. Navigation & View Switching
function setupNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const tab = item.getAttribute("data-tab");
      // If clicking Tool Checklist tab directly from sidebar, reset conflicting filters so full list shows
      switchTab(tab, tab === "checklist");
    });
  });

  // Rescan Tools button
  document.getElementById("btn-rescan").addEventListener("click", async () => {
    const btn = document.getElementById("btn-rescan");
    btn.innerHTML = "Scanning...";
    btn.disabled = true;
    try {
      await fetch("/api/scan", { method: "POST" });
      await loadData();
    } finally {
      btn.innerHTML = `<svg style="width: 15px; height: 15px; fill: currentColor;" viewBox="0 0 24 24"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg> Rescan Tools`;
      btn.disabled = false;
    }
  });

  // Top metric cards on Dashboard -> direct interactive jump
  const cardInstalled = document.getElementById("card-metric-installed");
  if (cardInstalled) {
    cardInstalled.onclick = () => {
      resetAllFilters();
      const instSelect = document.getElementById("filter-installed");
      if (instSelect) instSelect.value = "1";
      switchTab("checklist");
      renderTools();
    };
  }
  const cardTotal = document.getElementById("card-metric-total");
  if (cardTotal) {
    cardTotal.onclick = () => {
      resetAllFilters();
      switchTab("checklist");
      renderTools();
    };
  }
  const cardRuntime = document.getElementById("card-metric-runtime");
  if (cardRuntime) {
    cardRuntime.onclick = () => {
      switchTab("monitor");
    };
  }
  const cardMastery = document.getElementById("card-metric-mastery");
  if (cardMastery) {
    cardMastery.onclick = () => {
      resetAllFilters();
      switchTab("checklist");
      renderTools();
    };
  }

  // Modal Close
  document.getElementById("modal-close-btn").addEventListener("click", closeModal);
  document.getElementById("tool-modal").addEventListener("click", (e) => {
    if (e.target.id === "tool-modal") closeModal();
  });
}

function switchTab(tabId, resetFilters = false) {
  currentTab = tabId;
  document.querySelectorAll(".nav-item").forEach(el => {
    el.classList.toggle("active", el.getAttribute("data-tab") === tabId);
  });
  document.querySelectorAll(".tab-view").forEach(view => {
    view.style.display = view.id === `view-${tabId}` ? "block" : "none";
  });
  if (tabId === "checklist") {
    if (resetFilters) {
      resetAllFilters();
    } else {
      renderTools();
    }
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}
window.switchTab = switchTab;

// Global Reset for all search inputs and filters
function resetAllFilters() {
  currentCategory = "all";
  filterFavoritesOnly = false;

  const searchInput = document.getElementById("global-search");
  if (searchInput) searchInput.value = "";

  const srcSelect = document.getElementById("filter-source");
  if (srcSelect) srcSelect.value = "all";

  const instSelect = document.getElementById("filter-installed");
  if (instSelect) instSelect.value = "all";

  const statSelect = document.getElementById("filter-status");
  if (statSelect) statSelect.value = "all";

  const favBtn = document.getElementById("filter-favorites-btn");
  if (favBtn) favBtn.classList.remove("active");

  // Activate "all" category pill
  document.querySelectorAll("#category-filter-pills .pill-btn").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-cat") === "all");
  });

  renderTools();
}
window.resetAllFilters = resetAllFilters;

// Individual Filter Clear Helpers
function clearCategoryFilter() {
  currentCategory = "all";
  document.querySelectorAll("#category-filter-pills .pill-btn").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-cat") === "all");
  });
  renderTools();
}
window.clearCategoryFilter = clearCategoryFilter;

function clearSourceFilter() {
  const sel = document.getElementById("filter-source");
  if (sel) sel.value = "all";
  renderTools();
}
window.clearSourceFilter = clearSourceFilter;

function clearInstallFilter() {
  const sel = document.getElementById("filter-installed");
  if (sel) sel.value = "all";
  renderTools();
}
window.clearInstallFilter = clearInstallFilter;

function clearStatusFilter() {
  const sel = document.getElementById("filter-status");
  if (sel) sel.value = "all";
  renderTools();
}
window.clearStatusFilter = clearStatusFilter;

function clearSearchFilter() {
  const searchInput = document.getElementById("global-search");
  if (searchInput) searchInput.value = "";
  renderTools();
}
window.clearSearchFilter = clearSearchFilter;

function toggleFavoritesOnly() {
  filterFavoritesOnly = !filterFavoritesOnly;
  const favBtn = document.getElementById("filter-favorites-btn");
  if (favBtn) favBtn.classList.toggle("active", filterFavoritesOnly);
  renderTools();
}
window.toggleFavoritesOnly = toggleFavoritesOnly;

// 3. Search & Filter Handlers
function setupSearchAndFilters() {
  const searchInput = document.getElementById("global-search");
  searchInput.addEventListener("input", () => {
    renderTools();
  });

  // Secondary Filters
  document.getElementById("filter-source").addEventListener("change", renderTools);
  document.getElementById("filter-installed").addEventListener("change", renderTools);
  document.getElementById("filter-status").addEventListener("change", renderTools);

  const favBtn = document.getElementById("filter-favorites-btn");
  favBtn.addEventListener("click", () => {
    toggleFavoritesOnly();
  });
}

// Dynamically Render Category Filter Pills
function renderCategoryPills(categories, totalTools) {
  const container = document.getElementById("category-filter-pills");
  if (!container) return;

  const total = totalTools || allTools.length;
  let html = `<button class="pill-btn ${currentCategory === 'all' ? 'active' : ''}" data-cat="all">All Domains (${total})</button>`;

  (categories || []).forEach(cat => {
    const isAct = currentCategory === cat.category;
    html += `<button class="pill-btn ${isAct ? 'active' : ''}" data-cat="${escapeAttr(cat.category)}">${escapeHtml(cat.category)} (${cat.installed}/${cat.total})</button>`;
  });

  container.innerHTML = html;

  container.querySelectorAll(".pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      container.querySelectorAll(".pill-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentCategory = btn.getAttribute("data-cat");
      renderTools();
    });
  });
}

// 4. Data Loading
async function loadData() {
  try {
    const [toolsRes, statsRes] = await Promise.all([
      fetch("/api/tools").then(r => r.json()),
      fetch("/api/stats").then(r => r.json())
    ]);

    allTools = toolsRes.tools || [];
    renderDashboard(statsRes);
    renderTools();
    renderLiveTable(statsRes.live_active || []);
    renderTopToolsTable(statsRes.top_tools || []);
    renderRecentSessions(statsRes.recent_sessions || []);
    updateNetworkStatus(statsRes.internet_connected);
  } catch (err) {
    console.error("Failed to load CyberPulse data:", err);
  }
}

function updateNetworkStatus(isConnected) {
  const dot = document.getElementById("net-pulse-dot");
  const text = document.getElementById("net-status-text");
  if (isConnected) {
    dot.className = "pulse-dot";
    text.textContent = "Online / AI Ready";
    text.style.color = "var(--spotify-green)";
  } else {
    dot.className = "pulse-dot offline";
    text.textContent = "Air-Gapped / Offline";
    text.style.color = "var(--badge-missing)";
  }
}

// 5. Dashboard Rendering
function renderDashboard(stats) {
  document.getElementById("stat-installed").textContent = stats.installed_tools;
  document.getElementById("stat-total").textContent = stats.total_tools;
  document.getElementById("stat-missing-sub").textContent = `${stats.missing_tools} tools can be installed`;

  // Total runtime formatting
  const totalHours = (stats.total_time_seconds / 3600).toFixed(1);
  document.getElementById("stat-runtime").textContent = `${totalHours}h`;
  document.getElementById("stat-runs").textContent = `${stats.total_executions} executions tracked`;

  // Nav badges
  document.getElementById("nav-tool-count").textContent = stats.total_tools;

  // Dynamically populate category filter pills
  renderCategoryPills(stats.categories || [], stats.total_tools);

  // Dashboard summary: streak, weighted mastery, next recommended tool
  fetch("/api/dashboard/summary")
    .then(r => r.json())
    .then(summary => {
      // Streak
      const streakEl = document.getElementById("stat-streak");
      if (streakEl) streakEl.textContent = summary.streak || 0;

      // Weighted mastery ring
      const mastery = summary.mastery || {};
      const masteryPct = mastery.mastery_percent || 0;
      const masteryEl = document.getElementById("stat-mastery");
      if (masteryEl) masteryEl.textContent = `${masteryPct}%`;
      const subEl = document.getElementById("stat-mastery-sub");
      if (subEl) subEl.textContent = `${mastery.mastered || 0} mastered • ${(mastery.status_counts && mastery.status_counts.learning) || 0} learning`;
      const ring = document.getElementById("ring-mastery");
      const ringText = document.getElementById("ring-mastery-text");
      if (ring && ringText) {
        const circumference = 2 * Math.PI * 24;
        ring.style.strokeDasharray = circumference;
        ring.style.strokeDashoffset = circumference - (circumference * masteryPct) / 100;
        ringText.textContent = `${masteryPct}%`;
      }

      // Next recommended tool
      const nextTool = summary.next_tool;
      const nextEl = document.getElementById("stat-next-tool");
      const nextSub = document.getElementById("stat-next-tool-sub");
      if (nextEl) {
        nextEl.textContent = nextTool ? nextTool.display_name : "—";
        nextEl.title = nextTool ? nextTool.display_name : "";
      }
      if (nextSub && nextTool) {
        nextSub.textContent = `${nextTool.category} • ${nextTool.checklist_status}`;
      }
    })
    .catch(() => {
      document.getElementById("stat-streak").textContent = "0";
      document.getElementById("stat-mastery").textContent = "0%";
      document.getElementById("stat-next-tool").textContent = "—";
    });

  // Categories Breakdown Grid
  const catGrid = document.getElementById("category-cards-grid");
  catGrid.innerHTML = "";
  (stats.categories || []).forEach(cat => {
    const card = document.createElement("div");
    card.className = "metric-card";
    card.style.cursor = "pointer";
    card.innerHTML = `
      <div class="metric-header">
        <span class="metric-title">${escapeHtml(cat.category)}</span>
        <span class="badge badge-inst">${cat.installed} / ${cat.total}</span>
      </div>
      <div class="metric-value" style="font-size: 20px;">${cat.installed} Installed</div>
      <div class="metric-footer" style="color: var(--spotify-green);">Click to view tools &rarr;</div>
    `;
    card.addEventListener("click", () => {
      // Clear conflicting filters and search query so category tools definitely appear!
      const searchInput = document.getElementById("global-search");
      if (searchInput) searchInput.value = "";
      document.getElementById("filter-source").value = "all";
      document.getElementById("filter-installed").value = "all";
      document.getElementById("filter-status").value = "all";
      filterFavoritesOnly = false;
      const favBtn = document.getElementById("filter-favorites-btn");
      if (favBtn) favBtn.classList.remove("active");

      currentCategory = cat.category;

      // Update pill active button
      document.querySelectorAll("#category-filter-pills .pill-btn").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-cat") === cat.category);
      });

      switchTab("checklist");
      renderTools();
    });
    catGrid.appendChild(card);
  });

  // Installation Methods Breakdown Grid
  const srcGrid = document.getElementById("sources-cards-grid");
  if (srcGrid) {
    srcGrid.innerHTML = "";
    (stats.install_sources || []).forEach(src => {
      const card = document.createElement("div");
      card.className = "metric-card";
      card.style.cursor = "pointer";
      card.innerHTML = `
        <div class="metric-header">
          <span class="metric-title">${escapeHtml(src.source)}</span>
          <span class="badge badge-inst">${src.installed} / ${src.total}</span>
        </div>
        <div class="metric-value" style="font-size: 20px;">${src.installed} Active</div>
        <div class="metric-footer" style="color: var(--spotify-green);">Filter by ${escapeHtml(src.source)} &rarr;</div>
      `;
      card.addEventListener("click", () => {
        // Clear conflicting filters and search query
        const searchInput = document.getElementById("global-search");
        if (searchInput) searchInput.value = "";
        currentCategory = "all";
        document.getElementById("filter-installed").value = "all";
        document.getElementById("filter-status").value = "all";
        filterFavoritesOnly = false;
        const favBtn = document.getElementById("filter-favorites-btn");
        if (favBtn) favBtn.classList.remove("active");

        const sel = document.getElementById("filter-source");
        if (sel) sel.value = src.source;

        // Reset category pills to "All Domains"
        document.querySelectorAll("#category-filter-pills .pill-btn").forEach(btn => {
          btn.classList.toggle("active", btn.getAttribute("data-cat") === "all");
        });

        switchTab("checklist");
        renderTools();
      });
      srcGrid.appendChild(card);
    });
  }
}

function getSourceBadge(source) {
  const s = source || "APT (System)";
  let cls = "badge-source-apt";
  if (s.includes("Cargo") || s.includes("Rust")) cls = "badge-source-cargo";
  else if (s.includes("Go")) cls = "badge-source-go";
  else if (s.includes("GitHub")) cls = "badge-source-github";
  else if (s.includes("Snap")) cls = "badge-source-snap";
  else if (s.includes("Flatpak")) cls = "badge-source-flatpak";
  else if (s.includes("Pipx") || s.includes("Python")) cls = "badge-source-pipx";
  else if (s.includes("AppImage")) cls = "badge-source-appimage";
  else if (s.includes("/opt") || s.includes("Custom")) cls = "badge-source-custom";
  return `<span class="badge-source ${cls}">${escapeHtml(s)}</span>`;
}

// Helper to explain filter mismatch
function getFilterMismatchDescription(query, cat, src, inst, stat, favs) {
  const parts = [];
  if (query) parts.push(`search: "${escapeHtml(query)}"`);
  if (cat !== "all") parts.push(`domain: "${escapeHtml(cat)}"`);
  if (src !== "all") parts.push(`source: "${escapeHtml(src)}"`);
  if (inst !== "all") parts.push(inst === "1" ? "installed only" : "missing only");
  if (stat !== "all") parts.push(`status: "${escapeHtml(stat)}"`);
  if (favs) parts.push("favorites only");

  if (parts.length > 0) {
    return `Your active filter criteria (${parts.join(", ")}) matched 0 tools. Click the button below to clear all filters.`;
  }
  return "No tools found in the database. Try clicking 'Rescan Tools' in the top header.";
}

// 6. Tools Checklist Rendering
function renderTools() {
  const container = document.getElementById("tools-container");
  if (!container) return;

  const searchInput = document.getElementById("global-search");
  const query = (searchInput ? searchInput.value : "").toLowerCase().trim();
  const sourceFilter = document.getElementById("filter-source") ? document.getElementById("filter-source").value : "all";
  const installFilter = document.getElementById("filter-installed") ? document.getElementById("filter-installed").value : "all";
  const statusFilter = document.getElementById("filter-status") ? document.getElementById("filter-status").value : "all";

  const filtered = allTools.filter(tool => {
    if (query) {
      const matchName = (tool.name || "").toLowerCase().includes(query);
      const matchDisp = (tool.display_name || "").toLowerCase().includes(query);
      const matchDesc = (tool.description || "").toLowerCase().includes(query);
      const matchCat = (tool.category || "").toLowerCase().includes(query);
      const matchSrc = (tool.install_source || "").toLowerCase().includes(query);
      const matchPkg = (tool.package_name || "").toLowerCase().includes(query);
      const matchBin = (tool.binary_path || "").toLowerCase().includes(query);
      if (!matchName && !matchDisp && !matchDesc && !matchCat && !matchSrc && !matchPkg && !matchBin) return false;
    }

    if (currentCategory !== "all" && tool.category !== currentCategory) {
      return false;
    }

    if (sourceFilter !== "all") {
      const src = (tool.install_source || "APT (System)").trim();
      if (sourceFilter === "Custom /opt") {
        if (src !== "Custom /opt" && src !== "AppImage") return false;
      } else if (src.toLowerCase() !== sourceFilter.toLowerCase()) {
        return false;
      }
    }

    if (installFilter !== "all") {
      const isInst = tool.installed === 1;
      if (installFilter === "1" && !isInst) return false;
      if (installFilter === "0" && isInst) return false;
    }

    if (statusFilter !== "all" && tool.checklist_status !== statusFilter) {
      return false;
    }

    if (filterFavoritesOnly && !tool.is_favorite) {
      return false;
    }

    return true;
  });

  // Update Toolbar Result Count and Active Tags
  const countEl = document.getElementById("tools-result-count");
  if (countEl) {
    countEl.textContent = `Showing ${filtered.length} of ${allTools.length} tools`;
  }

  const tagsContainer = document.getElementById("active-filter-tags");
  if (tagsContainer) {
    const tags = [];
    if (query) {
      tags.push(`<span class="badge badge-inst" style="display:inline-flex; align-items:center; gap:5px;">Search: "${escapeHtml(query)}" <span onclick="clearSearchFilter()" style="cursor:pointer; font-weight:bold;">&times;</span></span>`);
    }
    if (currentCategory !== "all") {
      tags.push(`<span class="badge badge-inst" style="display:inline-flex; align-items:center; gap:5px;">${escapeHtml(currentCategory)} <span onclick="clearCategoryFilter()" style="cursor:pointer; font-weight:bold;">&times;</span></span>`);
    }
    if (sourceFilter !== "all") {
      tags.push(`<span class="badge badge-inst" style="display:inline-flex; align-items:center; gap:5px;">Source: ${escapeHtml(sourceFilter)} <span onclick="clearSourceFilter()" style="cursor:pointer; font-weight:bold;">&times;</span></span>`);
    }
    if (installFilter !== "all") {
      const label = installFilter === "1" ? "Installed Only" : "Missing Only";
      tags.push(`<span class="badge badge-inst" style="display:inline-flex; align-items:center; gap:5px;">${label} <span onclick="clearInstallFilter()" style="cursor:pointer; font-weight:bold;">&times;</span></span>`);
    }
    if (statusFilter !== "all") {
      tags.push(`<span class="badge badge-inst" style="display:inline-flex; align-items:center; gap:5px;">Status: ${escapeHtml(statusFilter)} <span onclick="clearStatusFilter()" style="cursor:pointer; font-weight:bold;">&times;</span></span>`);
    }
    if (filterFavoritesOnly) {
      tags.push(`<span class="badge badge-inst" style="display:inline-flex; align-items:center; gap:5px;">★ Favorites Only <span onclick="toggleFavoritesOnly()" style="cursor:pointer; font-weight:bold;">&times;</span></span>`);
    }
    tagsContainer.innerHTML = tags.join(" ");
  }

  // Handle Empty State
  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 50px 20px; text-align: center; background-color: var(--bg-card); border-radius: var(--radius-md); border: 1px dashed var(--border-subtle); margin-top: 10px;">
        <div style="font-size: 42px; margin-bottom: 12px;">🔍</div>
        <div style="font-size: 18px; font-weight: 700; margin-bottom: 8px; color: var(--text-primary);">No cybersecurity tools match your filters</div>
        <div style="color: var(--text-secondary); font-size: 14px; max-width: 520px; margin: 0 auto 20px auto; line-height: 1.5;">
          ${getFilterMismatchDescription(query, currentCategory, sourceFilter, installFilter, statusFilter, filterFavoritesOnly)}
        </div>
        <button class="btn btn-primary" onclick="resetAllFilters()" style="margin: 0 auto; display: inline-flex; align-items: center; gap: 8px;">
          <svg style="width: 16px; height: 16px; fill: currentColor;" viewBox="0 0 24 24"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>
          Clear All Filters &amp; Show All ${allTools.length} Tools
        </button>
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  filtered.forEach(tool => {
    const card = document.createElement("div");
    card.className = "tool-card";

    const isInstalled = tool.installed === 1;
    const badgeClass = isInstalled ? "badge-inst" : "badge-miss";
    const badgeText = isInstalled ? "Installed" : "To Install";

    card.innerHTML = `
      <div class="tool-card-header">
        <div class="tool-name-wrap">
          <div class="tool-display-name">${escapeHtml(tool.display_name)}</div>
          <div style="display: flex; align-items: center; gap: 8px; margin-top: 5px; flex-wrap: wrap;">
            <div class="tool-category-badge">${escapeHtml(tool.category)}</div>
            ${getSourceBadge(tool.install_source)}
          </div>
        </div>
        <button class="tool-fav-btn ${tool.is_favorite ? 'active' : ''}" title="Favorite" data-name="${tool.name}">
          ${tool.is_favorite ? '★' : '☆'}
        </button>
      </div>

      <div class="tool-description">${escapeHtml(tool.description)}</div>

      <div class="tool-card-footer">
        <span class="badge ${badgeClass}">${badgeText}</span>
        
        <select class="status-select tool-status-dropdown" data-name="${tool.name}">
          <option value="not_started" ${tool.checklist_status === 'not_started' ? 'selected' : ''}>Not Started</option>
          <option value="learning" ${tool.checklist_status === 'learning' ? 'selected' : ''}>Learning</option>
          <option value="practicing" ${tool.checklist_status === 'practicing' ? 'selected' : ''}>Practicing</option>
          <option value="mastered" ${tool.checklist_status === 'mastered' ? 'selected' : ''}>Mastered</option>
        </select>
      </div>
    `;

    // Click anywhere on card (except favorite/dropdown) opens details modal
    card.addEventListener("click", (e) => {
      if (e.target.closest(".tool-fav-btn") || e.target.closest(".tool-status-dropdown")) return;
      openModal(tool);
    });

    // Favorite button
    const favBtn = card.querySelector(".tool-fav-btn");
    favBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const newFav = tool.is_favorite ? 0 : 1;
      tool.is_favorite = newFav;
      favBtn.classList.toggle("active", newFav === 1);
      favBtn.textContent = newFav === 1 ? "★" : "☆";
      await fetch(`/api/tools/${tool.name}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ is_favorite: newFav })
      });
    });

    // Status dropdown
    const select = card.querySelector(".tool-status-dropdown");
    select.addEventListener("change", async (e) => {
      e.stopPropagation();
      const newStatus = select.value;
      tool.checklist_status = newStatus;
      await fetch(`/api/tools/${tool.name}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ checklist_status: newStatus })
      });
    });

    container.appendChild(card);
  });
}

// 7. Tool Modal Detail
function openModal(tool) {
  document.getElementById("modal-tool-name").textContent = tool.display_name;
  const badge = document.getElementById("modal-tool-badge");
  badge.className = `badge ${tool.installed ? 'badge-inst' : 'badge-miss'}`;
  badge.textContent = tool.installed ? `Installed (${tool.version || 'Active'})` : 'Missing (Checklist to Install)';

  const content = document.getElementById("modal-content");
  
  // Syntax examples HTML
  let syntaxHtml = "";
  if (tool.syntax_examples && tool.syntax_examples.length > 0) {
    syntaxHtml = tool.syntax_examples.map(ex => `
      <div style="margin-bottom: 8px;">
        <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 3px;">${escapeHtml(ex.desc || '')}</div>
        <div class="code-snippet">
          <span>${escapeHtml(ex.cmd || '')}</span>
          <button class="copy-btn" onclick="copySnippet('${escapeAttr(ex.cmd || '')}')">📋 Copy</button>
        </div>
      </div>
    `).join("");
  } else {
    syntaxHtml = `<div class="code-snippet"><span>${tool.name} --help</span><button class="copy-btn" onclick="copySnippet('${tool.name} --help')">📋</button></div>`;
  }

  // Real-world Incident Scenarios HTML
  let scenariosHtml = "";
  if (tool.scenarios && tool.scenarios.length > 0) {
    scenariosHtml = tool.scenarios.map(sc => `
      <div class="playbook-step" style="margin-bottom: 12px;">
        <div class="step-label">${escapeHtml(sc.title)} [${escapeHtml(sc.incident_type || '')}]</div>
        <div class="step-content" style="margin-bottom: 8px;">${escapeHtml(sc.description || '')}</div>
        ${(sc.steps || []).map(st => `<div style="font-size: 13px; color: var(--text-secondary); margin-left: 12px; margin-bottom: 4px;">• ${escapeHtml(st)}</div>`).join("")}
      </div>
    `).join("");
  } else {
    scenariosHtml = `<p style="font-size: 13px; color: var(--text-muted);">Standard penetration testing and digital forensic engagement usage.</p>`;
  }

  // Learning References HTML
  let refsHtml = "";
  if (tool.learning_refs && tool.learning_refs.length > 0) {
    refsHtml = tool.learning_refs.map(r => `
      <a href="${escapeAttr(r.url)}" target="_blank" class="btn btn-secondary" style="font-size: 12px; padding: 6px 14px; text-decoration: none;">
        🌐 ${escapeHtml(r.title)}
      </a>
    `).join(" ");
  }

  // Installation Command if missing
  let installSection = "";
  if (!tool.installed && tool.install_command) {
    installSection = `
      <div>
        <div class="modal-section-title">Install Command</div>
        <div class="code-snippet">
          <span>${escapeHtml(tool.install_command)}</span>
          <button class="copy-btn" onclick="copySnippet('${escapeAttr(tool.install_command)}')">📋 Copy</button>
        </div>
      </div>
    `;
  }

  content.innerHTML = `
    <div>
      <div class="modal-section-title">Tool Overview & Functionality</div>
      <p style="font-size: 14px; line-height: 1.6; color: var(--text-primary); margin-bottom: 10px;">${escapeHtml(tool.description)}</p>
      <div style="font-size: 12px; color: var(--text-muted); display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
        <div><strong>Category:</strong> ${escapeHtml(tool.category)}</div>
        <div><strong>Installation Method:</strong> ${getSourceBadge(tool.install_source)}</div>
        <div><strong>Binary / Location:</strong> <code>${escapeHtml(tool.binary_path || 'N/A')}</code></div>
      </div>
    </div>

    ${installSection}

    <div>
      <div class="modal-section-title">Syntax Cheatsheet & Key Commands</div>
      ${syntaxHtml}
    </div>

    <div>
      <div class="modal-section-title">Effective Scenarios & Incident Response</div>
      ${scenariosHtml}
    </div>

    <div>
      <div class="modal-section-title">Official References & Learning Resources</div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap;">${refsHtml}</div>
    </div>
  `;

  document.getElementById("tool-modal").classList.add("active");
}

function closeModal() {
  document.getElementById("tool-modal").classList.remove("active");
}

// 8. Live Monitor Management
function startLiveMonitor() {
  monitorInterval = setInterval(async () => {
    try {
      const res = await fetch("/api/monitor/live").then(r => r.json());
      renderLiveTable(res.processes || []);
      updateBottomBar(res.processes || []);
    } catch (err) {
      console.warn("Live monitor poll failed:", err);
    }
  }, 3000);
}

function renderLiveTable(processes) {
  const container = document.getElementById("live-monitor-table-container");
  const dashboardWrap = document.getElementById("active-processes-table-wrap");
  const countBadge = document.getElementById("active-processes-count");
  const navActive = document.getElementById("nav-active-count");

  navActive.textContent = processes.length;
  countBadge.textContent = `${processes.length} Running`;

  if (processes.length === 0) {
    const emptyMsg = `<p style="color: var(--text-muted); font-size: 13px;">No cybersecurity processes currently active. Background monitor polls system table every 3 seconds.</p>`;
    container.innerHTML = emptyMsg;
    dashboardWrap.innerHTML = emptyMsg;
    return;
  }

  const tableHtml = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Tool</th>
          <th>PID</th>
          <th>Active Time</th>
          <th>CPU %</th>
          <th>Memory</th>
          <th>Command Line</th>
        </tr>
      </thead>
      <tbody>
        ${processes.map(p => `
          <tr>
            <td><strong style="color: var(--spotify-green);">${escapeHtml(p.tool_name)}</strong></td>
            <td><code>${p.pid}</code></td>
            <td>${p.duration_formatted}</td>
            <td>${p.cpu_percent.toFixed(1)}%</td>
            <td>${p.memory_mb} MB</td>
            <td><code style="font-size: 11px;">${escapeHtml(p.cmdline)}</code></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;

  container.innerHTML = tableHtml;
  dashboardWrap.innerHTML = tableHtml;
}

function updateBottomBar(processes) {
  const toolNameEl = document.getElementById("bar-tool-name");
  const toolStatusEl = document.getElementById("bar-tool-status");
  const activeCountLabel = document.getElementById("bar-active-count-label");

  activeCountLabel.textContent = `${processes.length} tool${processes.length === 1 ? '' : 's'} active`;

  if (processes.length > 0) {
    const active = processes[0];
    toolNameEl.textContent = `Running: ${active.tool_name} (PID: ${active.pid})`;
    toolStatusEl.textContent = `Active Duration: ${active.duration_formatted} • CPU: ${active.cpu_percent}%`;
  } else {
    toolNameEl.textContent = "CyberPulse Monitor Active";
    toolStatusEl.textContent = `Scanning 260+ tools across Kali system`;
  }
}

function renderTopToolsTable(topTools) {
  const container = document.getElementById("top-usage-table-container");
  if (!topTools || topTools.length === 0) {
    container.innerHTML = `<p style="color: var(--text-muted); font-size: 13px;">No tool run statistics recorded yet. Execute tools from terminal to populate telemetry.</p>`;
    return;
  }

  container.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Tool</th>
          <th>Category</th>
          <th>Executions</th>
          <th>Total Runtime</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${topTools.map(t => {
          const hours = (t.total_seconds / 3600).toFixed(1);
          const isRun = t.currently_running === 1;
          return `
            <tr>
              <td><strong>${escapeHtml(t.display_name || t.tool_name)}</strong></td>
              <td><span style="color: var(--spotify-green);">${escapeHtml(t.category || '')}</span></td>
              <td>${t.total_runs} runs</td>
              <td>${hours} hours (${Math.round(t.total_seconds)}s)</td>
              <td><span class="badge ${isRun ? 'badge-inst' : 'badge-miss'}">${isRun ? 'ACTIVE NOW' : 'Idle'}</span></td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
}

function renderRecentSessions(sessions) {
  const container = document.getElementById("recent-sessions-container");
  if (!sessions || sessions.length === 0) {
    container.innerHTML = `<p style="color: var(--text-muted); font-size: 13px;">No recent execution logs.</p>`;
    return;
  }

  container.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Tool</th>
          <th>PID</th>
          <th>Duration</th>
          <th>Command Executed</th>
        </tr>
      </thead>
      <tbody>
        ${sessions.map(s => `
          <tr>
            <td style="color: var(--text-muted);">${escapeHtml(s.start_time.split("T")[1]?.slice(0, 8) || s.start_time)}</td>
            <td><strong style="color: var(--spotify-green);">${escapeHtml(s.tool_name)}</strong></td>
            <td><code>${s.pid}</code></td>
            <td>${s.duration_seconds.toFixed(1)}s</td>
            <td><code style="font-size: 11px;">${escapeHtml(s.cmdline)}</code></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

// 9. Scenario & Incident Advisor
function setupAdvisor() {
  const input = document.getElementById("scenario-input");
  const btn = document.getElementById("btn-run-advisor");
  const forceOfflineBox = document.getElementById("advisor-force-offline");

  // Preset chips
  document.querySelectorAll(".example-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const key = chip.getAttribute("data-preset");
      if (PRESETS[key]) {
        input.value = PRESETS[key];
        input.focus();
      }
    });
  });

  btn.addEventListener("click", async () => {
    const text = input.value.trim();
    if (!text) {
      alert("Please enter a scenario or incident description first.");
      return;
    }

    btn.disabled = true;
    btn.innerHTML = `<svg class="pulse-dot" style="display:inline-block; margin-right:8px;"></svg> Analyzing Incident...`;

    try {
      const res = await fetch("/api/advisor/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: text,
          force_offline: forceOfflineBox.checked
        })
      }).then(r => r.json());

      renderAdvisorOutput(res);
    } catch (err) {
      alert("Failed to analyze scenario: " + err.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<svg style="width: 16px; height: 16px; fill: currentColor;" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg> Analyze Incident & Recommend Tools`;
    }
  });
}

function renderAdvisorOutput(data) {
  const container = document.getElementById("advisor-output");
  container.style.display = "block";

  const pb = data.playbook || {};
  const mitreBadges = (data.mitre_mapping || []).map(m => `<span class="badge badge-inst" style="margin-right: 6px;">${escapeHtml(m)}</span>`).join("");

  const installedToolsHtml = (data.installed_tools || []).map(t => `
    <div class="tool-card" style="cursor: default;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
        <strong style="color: var(--text-primary); font-size: 15px;">${escapeHtml(t.display_name)}</strong>
        <span class="badge badge-inst">Installed & Ready</span>
      </div>
      <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">
        Binary: <code>${escapeHtml(t.binary_path || t.name)}</code>
      </div>
      ${(t.syntax_examples || []).map(ex => `
        <div class="code-snippet" style="margin-bottom: 6px; font-size: 12px;">
          <span>${escapeHtml(ex.cmd || '')}</span>
          <button class="copy-btn" onclick="copySnippet('${escapeAttr(ex.cmd || '')}')">📋</button>
        </div>
      `).join("")}
    </div>
  `).join("");

  const missingToolsHtml = (data.missing_tools || []).map(t => `
    <div class="tool-card" style="cursor: default;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
        <strong style="color: var(--text-primary); font-size: 15px;">${escapeHtml(t.display_name)}</strong>
        <span class="badge badge-miss">To Install</span>
      </div>
      <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">
        Package: <code>${escapeHtml(t.package_name || t.name)}</code>
      </div>
      <div class="code-snippet" style="margin-bottom: 6px; font-size: 12px;">
        <span>${escapeHtml(t.install_command || '')}</span>
        <button class="copy-btn" onclick="copySnippet('${escapeAttr(t.install_command || '')}')">📋 Copy</button>
      </div>
    </div>
  `).join("");

  container.innerHTML = `
    <div class="playbook-container">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
        <div>
          <div style="font-size: 12px; text-transform: uppercase; color: var(--spotify-green); font-weight: 700; margin-bottom: 4px;">
            ANALYSIS RESULT • ${escapeHtml(data.engine || 'Threat Engine')}
          </div>
          <h2 style="font-size: 22px; font-weight: 800;">Domain: ${escapeHtml(data.detected_domain)}</h2>
        </div>
        <span class="badge ${data.is_online ? 'badge-inst' : 'badge-miss'}" style="font-size: 12px;">
          ${data.is_online ? '● Internet Connected' : '○ Air-Gapped Mode'}
        </span>
      </div>

      <div style="display: flex; gap: 8px; flex-wrap: wrap;">
        ${mitreBadges}
      </div>

      <!-- Playbook Steps -->
      <div>
        <h3 style="font-size: 16px; font-weight: 800; margin-bottom: 12px;">Incident Response & Execution Playbook</h3>
        
        <div class="playbook-step" style="margin-bottom: 10px;">
          <div class="step-label">Stage 1: Triage & Reconnaissance</div>
          <div class="step-content">${escapeHtml(pb.stage_1_recon || 'Initial evidence preservation and asset discovery.')}</div>
        </div>

        <div class="playbook-step" style="margin-bottom: 10px;">
          <div class="step-label">Stage 2: Execution & Investigation</div>
          <div class="step-content">${escapeHtml(pb.stage_2_execution || 'Core vulnerability verification or payload inspection.')}</div>
        </div>

        <div class="playbook-step" style="margin-bottom: 10px;">
          <div class="step-label">Stage 3: Post-Analysis & Containment</div>
          <div class="step-content">${escapeHtml(pb.stage_3_post_exploit || 'Contain lateral movement and collect IOC artifacts.')}</div>
        </div>

        <div class="playbook-step" style="border-left-color: #FFA42B;">
          <div class="step-label" style="color: #FFA42B;">Remediation & Hardening</div>
          <div class="step-content">${escapeHtml(pb.remediation || 'Apply defense-in-depth security mitigations.')}</div>
        </div>
      </div>

      <!-- Recommended Tools on this System -->
      <div>
        <h3 style="font-size: 16px; font-weight: 800; margin-bottom: 12px;">
          Recommended Tools (${data.installed_count} Ready / ${data.missing_count} Available to Install)
        </h3>
        <div class="tools-grid" style="grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));">
          ${installedToolsHtml}
          ${missingToolsHtml}
        </div>
      </div>
    </div>
  `;

  container.scrollIntoView({ behavior: "smooth" });
}

// 9. Tool Manuals tab
function setupManual() {
  const btn = document.getElementById("btn-load-manual");
  const search = document.getElementById("manual-search");
  const content = document.getElementById("manual-content");
  const sourceBadge = document.getElementById("manual-source-badge");

  if (btn) {
    btn.addEventListener("click", async () => {
      const tool = (search && search.value) ? search.value.trim() : "";
      if (!tool) {
        content.innerHTML = '<p style="color: var(--text-muted);">Type a tool name (e.g. nmap, ffuf, hydra).</p>';
        return;
      }
      btn.textContent = "Loading...";
      btn.disabled = true;
      try {
        const res = await fetch(`/api/manual/${encodeURIComponent(tool)}`);
        if (!res.ok) {
          content.innerHTML = `<p style="color: var(--text-muted);">No local manual found for "${escapeHtml(tool)}".</p>`;
          sourceBadge.textContent = "";
          return;
        }
        const m = await res.json();
        renderManual(m);
      } catch (e) {
        content.innerHTML = '<p style="color: var(--text-muted);">Failed to load manual.</p>';
      } finally {
        btn.textContent = "Load Manual";
        btn.disabled = false;
      }
    });
  }

  const explainBtn = document.getElementById("btn-explain");
  const explainInput = document.getElementById("explain-input");
  const explainOutput = document.getElementById("explain-output");
  if (explainBtn && explainInput && explainOutput) {
    explainBtn.addEventListener("click", async () => {
      const command = explainInput.value.trim();
      if (!command) {
        explainOutput.innerHTML = '<p style="color: var(--text-muted);">Paste a command to explain.</p>';
        return;
      }
      explainBtn.textContent = "Explaining...";
      explainBtn.disabled = true;
      try {
        const res = await fetch("/api/manual/explain", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({command}),
        });
        if (!res.ok) throw new Error("explain failed");
        const data = await res.json();
        renderExplain(data);
      } catch (e) {
        explainOutput.innerHTML = '<p style="color: var(--text-muted);">Could not explain command.</p>';
      } finally {
        explainBtn.textContent = "Explain";
        explainBtn.disabled = false;
      }
    });
  }
}

function renderManual(m) {
  const content = document.getElementById("manual-content");
  const sourceBadge = document.getElementById("manual-source-badge");
  if (sourceBadge) {
    sourceBadge.textContent = `Source: ${(m.source || "curated").toUpperCase()}  |  ${m.banner || ""}`;
  }

  const optionsHtml = (m.options || []).map(o =>
    `<div style="display:flex;gap:10px;margin-bottom:4px;"><div style="font-family:monospace;font-size:12px;color:var(--spotify-green);min-width:110px;">${escapeHtml(o.flag || '')}</div><div style="font-size:13px;color:var(--text-primary);">${escapeHtml(o.description || '')}</div></div>`
  ).join("") || '<p style="font-size:13px;color:var(--text-muted);">No options parsed.</p>';

  const levels = ["Beginner", "Intermediate", "Advanced"];
  const examplesHtml = levels.map(lvl => {
    const exs = (m.examples || []).filter(e => e.level === lvl);
    if (exs.length === 0) return "";
    const items = exs.map(e => `
      <div class="playbook-step" style="margin-bottom:8px;">
        <div class="step-label" style="font-size:12px;color:var(--spotify-green);">${e.level} — ${escapeHtml(e.desc || '')}</div>
        <div class="code-snippet" style="margin-top:4px;">
          <span>${escapeHtml(e.cmd || '')}</span>
          <button class="copy-btn" onclick="copySnippet('${escapeAttr(e.cmd || '')}')">📋 Copy</button>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${m.banner || 'Authorised targets and your own lab only.'}</div>
      </div>
    `).join("");
    return `<div style="margin-bottom:14px;"><div style="font-weight:700;font-size:13px;margin-bottom:6px;color:var(--text-secondary);">${lvl}</div>${items}</div>`;
  }).join("") || '<p style="font-size:13px;color:var(--text-muted);">No worked examples.</p>';

  content.innerHTML = `
    <div style="font-size:15px;font-weight:700;margin-bottom:6px;color:var(--text-primary);">${escapeHtml(m.display_name || m.name)}</div>
    <div style="font-size:12px;color:var(--text-muted);margin-bottom:10px;">Category: ${escapeHtml(m.category || '')}</div>

    <div style="font-weight:700;font-size:13px;margin-bottom:4px;color:var(--text-secondary);">Purpose</div>
    <p style="font-size:13px;line-height:1.5;color:var(--text-primary);margin-bottom:10px;">${escapeHtml(m.purpose || 'No description available.')}</p>

    <div style="font-weight:700;font-size:13px;margin-bottom:4px;color:var(--text-secondary);">Install Check</div>
    <div class="code-snippet" style="margin-bottom:10px;">
      <span>${escapeHtml(m.install_check || `which ${m.name}`)}</span>
      <button class="copy-btn" onclick="copySnippet('${escapeAttr(m.install_check || `which ${m.name}`)}')">📋 Copy</button>
    </div>

    <div style="font-weight:700;font-size:13px;margin-bottom:4px;color:var(--text-secondary);">Most-used Options</div>
    <div style="margin-bottom:10px;">${optionsHtml}</div>

    <div style="font-weight:700;font-size:13px;margin-bottom:4px;color:var(--text-secondary);">Worked Examples</div>
    <div style="margin-bottom:10px;">${examplesHtml}</div>

    <div style="font-weight:700;font-size:13px;margin-bottom:4px;color:var(--text-secondary);">MITRE ATT&amp;CK</div>
    <p style="font-size:13px;color:var(--text-primary);margin-bottom:10px;">${escapeHtml((m.mitre || []).join(", ") || "—")}</p>

    <div style="font-weight:700;font-size:13px;margin-bottom:4px;color:var(--text-secondary);">Defensive View</div>
    <p style="font-size:13px;line-height:1.5;color:var(--text-primary);margin-bottom:10px;">${escapeHtml(m.defensive || `Defenders can detect ${m.name} via process-execution monitoring, network-flow logs, and endpoint EDR rules.`)}</p>

    <div style="font-size:11px;color:var(--text-muted);margin-top:10px;">${m.banner || 'Authorised targets and your own lab only.'}</p>
  `;
}

function renderExplain(data) {
  const output = document.getElementById("explain-output");
  const flagsHtml = (data.flags || []).map(f =>
    `<div style="display:flex;gap:10px;margin-bottom:3px;"><div style="font-family:monospace;font-size:12px;color:var(--spotify-green);min-width:130px;">${escapeHtml(f.flag || '')}</div><div style="font-size:13px;color:var(--text-primary);">${escapeHtml(f.description || '')}</div></div>`
  ).join("") || '<p style="font-size:13px;color:var(--text-muted);">No flags detected.</p>';
  output.innerHTML = `
    <div style="font-weight:700;font-size:13px;margin-bottom:6px;color:var(--text-secondary);">${escapeHtml(data.binary || 'command')}</div>
    <p style="font-size:13px;color:var(--text-primary);margin-bottom:8px;">${escapeHtml(data.summary || '')}</p>
    <div style="font-weight:700;font-size:12px;margin-bottom:4px;color:var(--text-secondary);">Flags / Arguments</div>
    <div>${flagsHtml}</div>
    ${data.placeholders && data.placeholders.length ? `<div style="font-size:11px;color:var(--text-muted);margin-top:6px;">Placeholders: ${data.placeholders.join(", ")}</div>` : ""}
    <div style="font-size:11px;color:var(--text-muted);margin-top:6px;">${data.banner || 'Authorised targets and your own lab only.'}</div>
  `;
}

// 9b. Health page
function setupHealth() {
  const refresh = document.getElementById("btn-health-refresh");
  const badge = document.getElementById("health-status-badge");
  const summary = document.getElementById("health-summary");
  const grid = document.getElementById("health-grid");
  const deps = document.getElementById("health-deps");

  async function loadHealth() {
    try {
      const res = await fetch("/api/health/detailed");
      if (!res.ok) throw new Error("health failed");
      const h = await res.json();

      if (badge) badge.textContent = (h.status || "unknown").toUpperCase();
      if (badge) badge.style.color = h.status === "healthy" ? "var(--spotify-green)" : "var(--text-muted)";
      if (summary) {
        const ai = h.ai || {};
        summary.innerHTML = `Internet: ${h.internet_connected ? "online" : "offline"} &bull; Collectors: ${h.live_active || 0} active &bull; AI: ${ai.enabled ? "enabled" : "off"} (redact: ${ai.redact_before_send ? "on" : "off"}) &bull; DB: ${(h.database && h.database.size_bytes ? (h.database.size_bytes / 1024).toFixed(1) : 0)} KB`;
      }

      if (grid) {
        const collectors = (h.collectors || []).map(c => `
          <div style="display:flex;justify-content:space-between;padding:6px 8px;border-bottom:1px solid var(--border-subtle);font-size:13px;">
            <div><strong>${escapeHtml(c.name)}</strong> <span style="color:var(--text-muted);">${c.enabled ? "enabled" : "disabled"}</span></div>
            <div style="color:var(--spotify-green-dim);">${c.available ? "available" : "unavailable"}</div>
          </div>
        `).join("") || "<p style='color:var(--text-muted);'>No collectors.</p>";
        grid.innerHTML = `<strong>COLLECTORS</strong><div style="margin-top:6px;">${collectors}</div>`;
      }

      if (deps) {
        const depList = (h.dependencies || []).map(d => `
          <div style="display:flex;justify-content:space-between;padding:4px 0;font-size:12px;">
            <span>${escapeHtml(d.name)}</span>
            <span style="color:${d.available ? 'var(--spotify-green)' : 'var(--text-muted)'};">${d.available ? 'OK' : 'MISSING'}</span>
          </div>
        `).join("");
        deps.innerHTML = depList;
        if (h.missing_dependencies && h.missing_dependencies.length) {
          deps.innerHTML += `<div style="margin-top:6px;color:var(--text-muted);font-size:12px;">Missing: ${h.missing_dependencies.join(", ")}</div>`;
        }
      }
    } catch (e) {
      if (badge) badge.textContent = "ERROR";
      if (summary) summary.textContent = "Could not load health data.";
    }
  }

  if (refresh) refresh.addEventListener("click", loadHealth);
  loadHealth();
}

// 9c. Session Timeline
function setupTimeline() {
  const refresh = document.getElementById("btn-timeline-refresh");
  const exportBtn = document.getElementById("btn-timeline-export");
  const filter = document.getElementById("timeline-filter");
  const list = document.getElementById("timeline-list");
  const summary = document.getElementById("timeline-summary");

  async function loadTimeline() {
    try {
      const res = await fetch("/api/sessions/timeline?limit=200");
      if (!res.ok) throw new Error("timeline failed");
      const data = await res.json();
      const sessions = data.sessions || [];
      const f = (filter && filter.value) ? filter.value.trim().toLowerCase() : "";
      const filtered = sessions.filter(s => !f || (s.tool_name || "").toLowerCase().includes(f));
      if (summary) summary.textContent = `${filtered.length} of ${sessions.length} session events`;
      if (list) {
        if (filtered.length === 0) {
          list.innerHTML = "<p style='color:var(--text-muted);'>No session events recorded yet.</p>";
        } else {
          list.innerHTML = filtered.map(s => {
            const start = s.start_time ? new Date(s.start_time).toLocaleString() : "-";
            const end = s.end_time ? new Date(s.end_time).toLocaleString() : "-";
            const dur = s.duration_seconds ? s.duration_seconds.toFixed(1) : 0;
            const cmd = escapeHtml(s.cmdline || "");
            return `
              <div style="border-bottom:1px solid var(--border-subtle);padding:10px 8px;font-size:13px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                  <div style="font-weight:700;color:var(--spotify-green);">${escapeHtml(s.tool_name || 'unknown')}</div>
                  <div style="color:var(--text-muted);font-size:11px;">${escapeHtml(s.source_method || '')}</div>
                </div>
                <div style="margin-bottom:4px;"><strong>PID:</strong> ${s.pid} &bull; <strong>Duration:</strong> ${dur}s &bull; <strong>Exit:</strong> ${s.exit_code ?? '-'}</div>
                <div style="margin-bottom:2px;"><strong>Start:</strong> ${start} &bull; <strong>End:</strong> ${end}</div>
                <div style="font-family:monospace;color:var(--text-primary);margin-top:4px;">${cmd}</div>
              </div>
            `;
          }).join("");
        }
      }
    } catch (e) {
      if (list) list.innerHTML = "<p style='color:var(--text-muted);'>Could not load timeline.</p>";
    }
  }

  if (refresh) refresh.addEventListener("click", loadTimeline);
  if (filter) filter.addEventListener("input", loadTimeline);
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      fetch("/api/sessions/timeline?limit=1000")
        .then(r => r.json())
        .then(data => {
          const sessions = data.sessions || [];
          let md = "# CyberPulse Lab Report\n\n";
          md += `Generated: ${new Date().toISOString()}\n\n`;
          md += `## Session Events (${sessions.length})\n\n`;
          sessions.forEach((s, i) => {
            md += `### ${i + 1}. ${s.tool_name || 'unknown'}\n`;
            md += `- **PID:** ${s.pid}  \n`;
            md += `- **Source:** ${s.source_method || '-'}  \n`;
            md += `- **Start:** ${s.start_time || '-'}  \n`;
            md += `- **End:** ${s.end_time || '-'}  \n`;
            md += `- **Duration:** ${(s.duration_seconds || 0).toFixed(1)}s  \n`;
            md += `- **Exit Code:** ${s.exit_code ?? '-'}  \n`;
            md += `- **Command:** \`${(s.cmdline || '').replace(/`/g, '\\`')}\`  \n\n`;
          });
          const blob = new Blob([md], {type: "text/markdown"});
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `cyberpulse_lab_report_${new Date().toISOString().slice(0,10)}.md`;
          a.click();
          URL.revokeObjectURL(url);
        })
        .catch(() => alert("Export failed."));
    });
  }
  loadTimeline();
}

// 9d. Command Palette (Ctrl+K)
function setupPalette() {
  const overlay = document.getElementById("palette-overlay");
  const input = document.getElementById("palette-input");
  const results = document.getElementById("palette-results");
  const closeBtn = document.getElementById("palette-close-btn");
  let activeIndex = -1;

  function openPalette() {
    overlay.style.display = "flex";
    input.focus();
    input.value = "";
    results.innerHTML = "";
    activeIndex = -1;
  }

  function closePalette() {
    overlay.style.display = "none";
    input.blur();
    activeIndex = -1;
  }

  function renderResults(items) {
    if (!items || items.length === 0) {
      results.innerHTML = "<div style='padding:12px 14px;color:var(--text-muted);'>No results.</div>";
      return;
    }
    results.innerHTML = items.map((r, i) => {
      const typeLabel = r.type === "tool" ? "Tool" : r.type === "manual" ? "Manual" : "Scenario";
      const highlighted = r.title.replace(
        new RegExp(`(${escapeHtmlRegExp(r.query || "")})`, "gi"),
        "<mark>$1</mark>"
      );
      return `
        <div class="palette-item" data-index="${i}" style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--border-subtle);">
          <div style="display:flex;flex:1;gap:10px;">
            <div style="font-size:11px;color:var(--spotify-green-dim);font-weight:700;text-transform:uppercase;width:44px;">${escapeHtml(typeLabel)}</div>
            <div><div style="font-weight:700;color:var(--text-primary);">${highlighted}</div><div style="font-size:12px;color:var(--text-muted);">${escapeHtml(r.subtitle || "")}</div></div>
          </div>
          <div style="color:var(--spotify-green);">&#9656;</div>
        </div>
      `;
    }).join("");
    results.querySelectorAll(".palette-item").forEach(el => {
      el.addEventListener("click", () => {
        const idx = Number(el.getAttribute("data-index"));
        navigateTo(items[idx]);
        closePalette();
      });
    });
  }

  function escapeHtmlRegExp(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  async function search(query) {
    try {
      const res = await fetch(`/api/search?q=${encodeURIComponent(query)}&limit=8`);
      if (!res.ok) throw new Error("search failed");
      const data = await res.json();
      renderResults(data.results || []);
    } catch (e) {
      results.innerHTML = "<div style='padding:12px 14px;color:var(--text-muted);'>Search unavailable.</div>";
    }
  }

  function navigateTo(r) {
    if (r.type === "tool") {
      const searchInput = document.getElementById("global-search");
      if (searchInput) searchInput.value = r.title;
      switchTab("checklist");
      renderTools();
    } else if (r.type === "manual") {
      const mInput = document.getElementById("manual-search");
      if (mInput) mInput.value = r.title;
      switchTab("manual");
      const btn = document.getElementById("btn-load-manual");
      if (btn) btn.click();
    } else if (r.type === "scenario") {
      const sInput = document.getElementById("scenario-input");
      if (sInput) sInput.value = r.title;
      switchTab("advisor");
    }
  }

  if (closeBtn) closeBtn.addEventListener("click", closePalette);
  if (overlay) {
    overlay.addEventListener("click", e => { if (e.target === overlay) closePalette(); });
  }
  if (input) {
    input.addEventListener("keydown", e => {
      if (e.key === "Escape") closePalette();
      else if (e.key === "ArrowDown") { e.preventDefault(); activeIndex = Math.min(activeIndex + 1, (results.querySelectorAll(".palette-item").length || 1) - 1); highlightItem(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); activeIndex = Math.max(activeIndex - 1, -1); highlightItem(); }
      else if (e.key === "Enter") {
        e.preventDefault();
        const items = results.querySelectorAll(".palette-item");
        if (activeIndex >= 0 && items[activeIndex]) items[activeIndex].click();
        else if (items[0]) items[0].click();
      }
    });
    input.addEventListener("input", () => {
      activeIndex = -1;
      const q = input.value.trim();
      if (q.length >= 1) search(q);
      else results.innerHTML = "";
    });
  }

  document.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openPalette();
    }
  });

  function highlightItem() {
    const items = results.querySelectorAll(".palette-item");
    items.forEach((el, i) => {
      el.style.background = i === activeIndex ? "var(--bg-card-hover)" : "";
    });
  }
}

// 9e. Guided Workflows
function setupWorkflows() {
  const grid = document.getElementById("workflows-grid");
  const panel = document.getElementById("workflow-panel");
  const modeTitle = document.getElementById("workflow-mode-title");
  const modeSub = document.getElementById("workflow-mode-sub");
  const modeContent = document.getElementById("workflow-mode-content");
  const backBtn = document.getElementById("workflow-back");
  const actionBtn = document.getElementById("workflow-action");
  let currentMode = null;
  let currentTool = null;

  const modes = [
    { id: "learn", title: "Learn", sub: "Read a tool manual, try an example, mark progress", icon: "L" },
    { id: "practice", title: "Practice", sub: "Run a lab session, log findings, track time", icon: "P" },
    { id: "investigate", title: "Investigate", sub: "Paste an incident, get a playbook, tick steps off", icon: "I" },
    { id: "report", title: "Report", sub: "Turn a session into a Markdown lab report", icon: "R" },
  ];

  if (grid) {
    grid.innerHTML = modes.map(m => `
      <div class="metric-card" style="cursor:pointer;" data-mode="${m.id}">
        <div class="metric-header">
          <span class="metric-title">${m.title}</span>
          <div class="metric-icon">${m.icon}</div>
        </div>
        <div class="metric-value" style="font-size:13px;color:var(--text-secondary);">${m.sub}</div>
        <div class="metric-footer" style="color:var(--spotify-green);font-size:12px;">Start &rarr;</div>
      </div>
    `).join("");
    grid.querySelectorAll(".metric-card").forEach(card => {
      card.addEventListener("click", () => {
        currentMode = card.getAttribute("data-mode");
        showPanel(currentMode);
      });
    });
  }

  function showPanel(mode) {
    currentMode = mode;
    const m = modes.find(x => x.id === mode);
    grid.style.display = "none";
    panel.style.display = "";
    modeTitle.textContent = m.title;
    modeSub.textContent = m.sub;
    modeContent.innerHTML = "";
    if (mode === "learn") renderLearn();
    else if (mode === "practice") renderPractice();
    else if (mode === "investigate") renderInvestigate();
    else if (mode === "report") renderReport();
    actionBtn.style.display = "none";
  }

  if (backBtn) backBtn.addEventListener("click", () => {
    panel.style.display = "none";
    grid.style.display = "";
    currentMode = null;
    currentTool = null;
  });

  async function renderLearn() {
    try {
      const res = await fetch("/api/tools?installed=1&limit=40");
      const data = await res.json();
      const tools = data.tools || [];
      let html = `<div style="font-size:13px;color:var(--text-muted);margin-bottom:10px;">Pick an installed tool, open its manual, and mark your mastery progress.</div>`;
      html += `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">`;
      tools.slice(0, 24).forEach(t => {
        html += `<button class="pill-btn learn-tool" data-tool="${escapeHtml(t.name)}">${escapeHtml(t.display_name || t.name)}</button>`;
      });
      html += `</div>`;
      html += `<div id="learn-detail" style="margin-top:12px;"></div>`;
      modeContent.innerHTML = html;
      actionBtn.style.display = "none";
      modeContent.querySelectorAll(".learn-tool").forEach(btn => {
        btn.addEventListener("click", () => {
          currentTool = btn.getAttribute("data-tool");
          actionBtn.style.display = "inline-block";
          actionBtn.textContent = "View Manual";
          actionBtn.onclick = () => {
            const mInput = document.getElementById("manual-search");
            if (mInput) mInput.value = currentTool;
            switchTab("manual");
            const b = document.getElementById("btn-load-manual");
            if (b) b.click();
            backBtn.click();
          };
          const detail = document.getElementById("learn-detail");
          detail.innerHTML = `<div style="margin-top:10px;padding:10px;background:var(--bg-card);border-radius:var(--radius-sm);">
            <div style="font-weight:700;">${escapeHtml(currentTool)}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Open the Manual tab to view the full local manual and worked examples.</div>
            <div style="margin-top:8px;">
              <button class="pill-btn" onclick="setLearnStatus('not_started')">Not Started</button>
              <button class="pill-btn" onclick="setLearnStatus('learning')">Learning</button>
              <button class="pill-btn" onclick="setLearnStatus('practicing')">Practicing</button>
              <button class="pill-btn" onclick="setLearnStatus('mastered')">Mastered</button>
            </div>
            <div id="learn-status-msg" style="font-size:12px;color:var(--spotify-green);margin-top:6px;"></div>
          </div>`;
        });
      });
    } catch (e) {
      modeContent.innerHTML = "<p style='color:var(--text-muted);'>Unable to load tools.</p>";
    }
  }

  window.setLearnStatus = async (status) => {
    if (!currentTool) return;
    try {
      await fetch(`/api/tools/${encodeURIComponent(currentTool)}/status`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({checklist_status: status}),
      });
      const msg = document.getElementById("learn-status-msg");
      if (msg) msg.textContent = `Marked ${currentTool} as ${status}.`;
      setTimeout(() => { if (msg) msg.textContent = ""; }, 2000);
    } catch (e) {
      alert("Failed to update status.");
    }
  };

  function renderPractice() {
    modeContent.innerHTML = `
      <div style="font-size:13px;color:var(--text-muted);margin-bottom:10px;">Start a lab session to log target, notes, and tools used.</div>
      <div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap;">
        <input id="practice-name" class="search-input" placeholder="Session name" style="flex:1;min-width:140px;">
        <input id="practice-target" class="search-input" placeholder="Target (e.g. 10.0.0.0/24)" style="flex:1;min-width:140px;">
        <input id="practice-notes" class="search-input" placeholder="Notes" style="flex:1;min-width:140px;">
        <input id="practice-tools" class="search-input" placeholder="Tools (comma-separated)" style="flex:1;min-width:140px;">
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary" id="practice-start">Start Session</button>
        <button class="btn btn-secondary" id="practice-stop">Stop Session</button>
      </div>
      <div id="practice-msg" style="font-size:12px;color:var(--spotify-green);margin-top:8px;"></div>
      <div id="practice-list" style="margin-top:14px;font-size:13px;"></div>
    `;
    actionBtn.style.display = "none";
    document.getElementById("practice-start").addEventListener("click", async () => {
      const sid = "lab-" + Date.now();
      const name = document.getElementById("practice-name").value || sid;
      const target = document.getElementById("practice-target").value || "";
      const notes = document.getElementById("practice-notes").value || "";
      const tools = document.getElementById("practice-tools").value.split(",").map(s=>s.trim()).filter(Boolean);
      try {
        await fetch("/api/lab/sessions", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({session_id:sid,name,target,notes,tools})});
        document.getElementById("practice-msg").textContent = `Started session "${name}".`;
        loadPracticeList();
      } catch(e){ alert("Failed to start session."); }
    });
    document.getElementById("practice-stop").addEventListener("click", async () => {
      try {
        const res = await fetch("/api/lab/sessions");
        const data = await res.json();
        const active = (data.sessions||[]).find(s=>s.status==="active");
        if (active) {
          await fetch(`/api/lab/sessions/${active.session_id}/stop`, {method:"POST"});
          document.getElementById("practice-msg").textContent = `Stopped session "${active.name}".`;
          loadPracticeList();
        } else {
          document.getElementById("practice-msg").textContent = "No active session.";
        }
      } catch(e){ alert("Failed to stop session."); }
    });
    loadPracticeList();
  }

  async function loadPracticeList() {
    try {
      const res = await fetch("/api/lab/sessions?limit=10");
      const data = await res.json();
      const el = document.getElementById("practice-list");
      if (!el) return;
      if (!(data.sessions||[]).length) { el.innerHTML = "<p style='color:var(--text-muted);'>No lab sessions yet.</p>"; return; }
      el.innerHTML = (data.sessions||[]).map(s => `
        <div style="padding:6px 8px;border-bottom:1px solid var(--border-subtle);font-size:12px;display:flex;justify-content:space-between;">
          <div><strong>${escapeHtml(s.name||'')}</strong> <span style="color:var(--text-muted);">${s.status}</span></div>
          <div style="color:var(--spotify-green-dim);">${s.target||'-'}</div>
        </div>
      `).join("");
    } catch(e){}
  }

  function renderInvestigate() {
    modeContent.innerHTML = `
      <div style="font-size:13px;color:var(--text-muted);margin-bottom:10px;">Paste an incident to get a phased playbook, then save it as a session.</div>
      <textarea id="investigate-input" class="scenario-textarea" placeholder="Paste an incident alert or objective..." style="width:100%;min-height:110px;margin-bottom:10px;"></textarea>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary" id="investigate-analyze">Analyze</button>
        <button class="btn btn-secondary" id="investigate-save" style="display:none;">Save as Session</button>
      </div>
      <div id="investigate-output" style="margin-top:14px;"></div>
    `;
    actionBtn.style.display = "none";
    document.getElementById("investigate-analyze").addEventListener("click", async () => {
      const text = document.getElementById("investigate-input").value.trim();
      if (!text) { alert("Enter a scenario."); return; }
      try {
        const res = await fetch("/api/advisor/analyze", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({scenario:text, force_offline:true})});
        const d = await res.json();
        let html = `<div style="font-weight:700;margin-bottom:6px;">${escapeHtml(d.detected_domain||'')}</div>`;
        html += `<div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">${escapeHtml(d.summary||'')}</div>`;
        html += `<div style="font-weight:700;margin-bottom:4px;">Playbook</div>`;
        const pb = d.playbook||{};
        html += `<div style="margin-bottom:4px;"><strong>1. Triage:</strong> ${escapeHtml(pb.stage_1_recon||'')}</div>`;
        html += `<div style="margin-bottom:4px;"><strong>2. Execute:</strong> ${escapeHtml(pb.stage_2_execution||'')}</div>`;
        html += `<div style="margin-bottom:8px;"><strong>3. Post:</strong> ${escapeHtml(pb.stage_3_post_exploit||'')}</div>`;
        html += `<div style="font-weight:700;margin-bottom:4px;">Remediation</div>`;
        html += `<div style="font-size:13px;color:var(--text-primary);">${escapeHtml(pb.remediation||'')}</div>`;
        document.getElementById("investigate-output").innerHTML = html;
        document.getElementById("investigate-save").style.display = "inline-block";
        document.getElementById("investigate-save").onclick = async () => {
          const sid = "inv-" + Date.now();
          await fetch("/api/lab/sessions", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({session_id:sid,name:"Investigation",target:text.slice(0,80),notes:text,tools:(d.recommended_tools||[]).map(t=>t.name)})});
          document.getElementById("investigate-save").textContent = "Saved as session.";
        };
      } catch(e){ alert("Analysis failed."); }
    });
  }

  function renderReport() {
    modeContent.innerHTML = `
      <div style="font-size:13px;color:var(--text-muted);margin-bottom:10px;">Export session events as a Markdown lab report (objective, method, evidence, findings, remediation).</div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary" id="report-export">Export Lab Report (.md)</button>
      </div>
      <div id="report-msg" style="font-size:12px;color:var(--spotify-green);margin-top:8px;"></div>
    `;
    actionBtn.style.display = "none";
    document.getElementById("report-export").addEventListener("click", () => {
      const btn = document.getElementById("report-export");
      btn.textContent = "Exporting...";
      fetch("/api/sessions/timeline?limit=1000")
        .then(r=>r.json())
        .then(data=>{
          const sessions = data.sessions||[];
          let md = "# CyberPulse Lab Report\n\n";
          md += `Generated: ${new Date().toISOString()}\n\n`;
          md += `## Session Events (${sessions.length})\n\n`;
          sessions.forEach((s,i)=>{
            md += `### ${i+1}. ${s.tool_name||'unknown'}\n`;
            md += `- **PID:** ${s.pid}  \n`;
            md += `- **Source:** ${s.source_method||'-'}  \n`;
            md += `- **Start:** ${s.start_time||'-'}  \n`;
            md += `- **End:** ${s.end_time||'-'}  \n`;
            md += `- **Duration:** ${(s.duration_seconds||0).toFixed(1)}s  \n`;
            md += `- **Exit Code:** ${s.exit_code??'-'}  \n`;
            md += `- **Command:** \`${(s.cmdline||'').replace(/`/g,'\\`')}\`  \n\n`;
          });
          const blob=new Blob([md],{type:"text/markdown"});
          const url=URL.createObjectURL(blob);
          const a=document.createElement("a");
          a.href=url; a.download=`cyberpulse_lab_report_${new Date().toISOString().slice(0,10)}.md`;
          a.click(); URL.revokeObjectURL(url);
          document.getElementById("report-msg").textContent = "Report exported.";
          btn.textContent = "Export Lab Report (.md)";
        })
        .catch(()=>{ btn.textContent = "Export Lab Report (.md)"; alert("Export failed."); });
    });
  }
}

// 10. Uptime counter
function updateUptimeTimer() {
  uptimeSeconds++;
  const hours = Math.floor(uptimeSeconds / 3600);
  const mins = Math.floor((uptimeSeconds % 3600) / 60);
  const secs = uptimeSeconds % 60;
  document.getElementById("bar-session-timer").textContent = `Uptime: ${pad(hours)}h ${pad(mins)}m ${pad(secs)}s`;
}

function pad(n) {
  return n < 10 ? '0' + n : n;
}

function copySnippet(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert("Copied to clipboard: " + text);
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(str) {
  if (!str) return "";
  return String(str).replace(/'/g, "\\'");
}
