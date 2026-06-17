function app() {
  return {
    phase: 'upload',
    initializing: true,
    loading: false,
    error: '',
    selectedFile: null,
    password: '',
    language: '',
    project: null,
    publicMode: false,
    // UI theme — 'default' (Tailwind-Standard) | 'voltlogik' (Anthrazit + Kupfer)
    // Reihenfolge: localStorage (explizite User-Wahl) → Server-Default (ENV OPENKNXVIEWER_THEME) → 'default'
    theme: (typeof localStorage !== 'undefined' && localStorage.getItem('openknxviewer-theme')) || 'default',
    themeUserChosen: (typeof localStorage !== 'undefined' && !!localStorage.getItem('openknxviewer-theme')),
    demoAvailable: false,
    lastProjectFilename: '',
    recentProjects: [],
    selectedRecentSlug: null,
    currentProjectSlug: null,
    projectNotes: {},
    notesModalOpen: false,
    notesModalSlug: null,
    notesModalTitle: '',
    notesModalText: '',
    activeTab: 'info',
    toolsMenuOpen: false,
    toolsGroupIds: ['communication', 'bus_scan', 'compare', 'snapshots'],
    tabs: [
      { id: 'info', label: 'Info' },
      { id: 'devices', label: 'Geräte' },
      { id: 'group_addresses', label: 'Gruppenadressen' },
      { id: 'topology', label: 'Topologie' },
      { id: 'locations', label: 'Standorte' },
      { id: 'com_objects', label: 'Kommunikationsobjekte' },
      { id: 'functions', label: 'Funktionen' },
      { id: 'communication', label: 'Graph' },
      { id: 'bus_monitor', label: 'Bus-Monitor' },
      { id: 'bus_scan', label: 'Bus-Scan' },
      { id: 'ki_analyse', label: 'KI-Analyse' },
      { id: 'compare', label: 'Vergleichen' },
      { id: 'snapshots', label: 'Snapshots' },
    ],
    deviceSearch: '',
    gaSearch: '',
    coSearch: '',
    expandedTopology: new Set(),
    expandedCODevices: new Set(),
    highlightedCO: null,

    // WebSocket & Live-Monitor state
    ws: null,
    wsStatus: 'disconnected',
    gatewayIP: '',
    gatewayPort: 3671,
    gatewayLanguage: 'de-DE',
    gatewayError: '',
    showGatewayConfig: false,
    exportDetailed: true,
    connectionType: 'local',
    remoteGatewayToken: '',
    remoteGatewayConnected: false,
    tokenCopied: false,
    currentValues: {},
    liveLog: [],
    liveLogFilter: '',
    liveLogPaused: false,

    // GA write / read-all
    gaWriteValues: {},
    readingAll: false,

    // Global search (Cmd-K)
    searchOpen: false,
    searchQuery: '',
    searchIndex: 0,

    // GA activity sparkline buffer: { [ga]: [{ts, num, bool}] }
    gaHistory: {},
    gaHistoryMax: 50,

    // Snapshots
    snapshots: [],
    snapshotName: '',
    snapshotSaving: false,
    diffA: '',
    diffB: 'current',
    diffLoading: false,
    diffRows: [],
    diffStats: null,
    diffOnlyChanges: true,

    // LLM
    llmApiKey: '',
    llmModel: 'z-ai/glm-5',
    llmConfigured: false,
    llmProvider: 'openrouter',  // 'openrouter' | 'local'
    lmStudioAvailable: false,
    lmStudioModels: ['local-model'],
    llmLocalUrl: 'http://localhost:1234/v1',
    llmLocalToken: '',
    llmLocalTokenSet: false,
    llmQuestion: '',
    llmResponse: '',
    llmReasoning: '',
    llmLoading: false,
    llmError: '',
    llmMessages: [],  // Chat history: [{role: 'user'|'assistant', content: string}]
    llmIncludeBus: false,
    llmBusLimit: 100,

    // Projektvergleich
    compareSlug: null,
    compareProject: null,
    compareLoading: false,
    compareError: '',
    compareDiff: null,
    compareLlmResponse: '',
    compareLlmReasoning: '',
    compareLlmLoading: false,
    compareLlmError: '',

    // Annotations (editable device/GA metadata)
    annotations: { devices: {}, group_addresses: {} },
    editingKey: '',
    editValue: '',

    // WireGuard
    wireguardEnabled: false,
    wireguardLatencyMs: null,
    wireguardPeerConnected: false,
    wireguardAllowedActions: ['monitor'],
    wireguardEtsPortActive: false,
    showWgSetup: false,
    wgSetupData: { server_ip: '10.100.0.1', peer_ip: '10.100.0.2', listen_port: 51820, ets_port: 13671, knx_ip: '', knx_port: 3671, server_public_ip: '' },
    wgSetupResult: '',
    wgSetupError: '',

    // Kommunikationsgraph
    commNetwork: null,
    commGraphFilter: '',
    commGraphReady: false,
    commSelectedNode: null,
    commGraphStats: null,
    _commNodes: null,
    _commEdges: null,
    _commAllNodes: null,
    _commAllEdges: null,

    // Bus-Scan state
    progModeLoading: false,
    progModeResults: [],
    progModeScanned: false,
    progModeError: '',
    progModeTimeout: 3,
    paScanning: false,
    paScanProgress: 0,
    paScanTotal: 0,
    paScanFound: [],
    paScanDone: false,
    paScanCancelled: false,
    scanArea: '',
    scanLine: '',
    scanDevice: '',
    scanTimeoutMs: 1500,
    gaScanning: false,
    gaScanProgress: 0,
    gaScanTotal: 0,
    gaScanDone: false,
    gaScanCancelled: false,
    gaScanResponded: 0,
    gaScanStart: '0/0/1',
    gaScanEnd: '5/7/255',
    gaScanDelayMs: 100,
    devicePropsModal: false,
    devicePropsAddr: '',
    devicePropsData: null,
    devicePropsLoading: false,
    devicePropsError: '',
    gatewayDescription: null,
    gatewayDescLoading: false,
    gatewayDescError: '',

    async init() {
      window.__knxNavDevice = (addr) => {
        this.deviceSearch = addr;
        this.activeTab = 'devices';
      };
      window.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
          e.preventDefault();
          this.openSearch();
        }
      });
      try {
        const res = await fetch('/api/mode');
        const mode = await res.json();
        this.publicMode = mode.public ?? false;
        // Server-Default-Theme (aus ENV OPENKNXVIEWER_THEME) nur dann übernehmen,
        // wenn der User lokal noch keine eigene Wahl getroffen hat.
        if (!this.themeUserChosen && mode.default_theme) {
          this.theme = (mode.default_theme === 'voltlogik') ? 'voltlogik' : 'default';
        }
      } catch (_) { /* default false */ }
      document.title = 'Open-KNXViewer';
      if (!this.publicMode) {
        this.connectWebSocket();
        this.loadAnnotations();
        this.loadRecentProjects();
        this.loadProjectNotes();
        this.loadLlmConfig();
        this.loadGatewayInfo();
        // Show upload screen — user selects project from sidebar
      } else {
        try {
          const res = await fetch('/api/demo/available');
          if (res.ok) this.demoAvailable = (await res.json()).available;
        } catch (_) {}
      }
      this.$watch('activeTab', (tab) => {
        if (tab === 'communication' && this.project && !this.commGraphReady) {
          this.$nextTick(() => this.buildCommGraph());
        }
      });
      this.initializing = false;
    },

    setTheme(t) {
      this.theme = (t === 'voltlogik') ? 'voltlogik' : 'default';
      this.themeUserChosen = true;
      try { localStorage.setItem('openknxviewer-theme', this.theme); } catch (_) {}
    },

    async resetThemeToServerDefault() {
      try { localStorage.removeItem('openknxviewer-theme'); } catch (_) {}
      this.themeUserChosen = false;
      try {
        const res = await fetch('/api/mode');
        const mode = await res.json();
        this.theme = (mode.default_theme === 'voltlogik') ? 'voltlogik' : 'default';
      } catch (_) {
        this.theme = 'default';
      }
    },

    async loadAnnotations() {
      try {
        const res = await fetch('/api/annotations');
        if (res.ok) this.annotations = await res.json();
      } catch (_) {}
    },

    async loadGatewayInfo() {
      try {
        const res = await fetch('/api/gateway');
        if (res.ok) {
          const cfg = await res.json();
          this.connectionType = cfg.connection_type || 'local';
          this.remoteGatewayToken = cfg.remote_gateway_token || '';
        }
      } catch (_) {}
      try {
        const wgRes = await fetch('/api/wireguard/status');
        if (wgRes.ok) {
          const wg = await wgRes.json();
          this.wireguardEnabled = wg.enabled || false;
          this.wireguardLatencyMs = wg.latency_ms ?? null;
          this.wireguardPeerConnected = wg.peer_connected || false;
          this.wireguardAllowedActions = wg.allowed_actions || ['monitor'];
          this.wireguardEtsPortActive = wg.ets_port_active || false;
        }
        const wgCfgRes = await fetch('/api/wireguard/config');
        if (wgCfgRes.ok) {
          const wgCfg = await wgCfgRes.json();
          this.wgSetupData.server_ip = wgCfg.wireguard_server_ip || '10.100.0.1';
          this.wgSetupData.peer_ip = wgCfg.wireguard_peer_ip || '10.100.0.2';
          this.wgSetupData.listen_port = wgCfg.wireguard_listen_port || 51820;
          this.wgSetupData.ets_port = wgCfg.wireguard_ets_port || 13671;
          this.wgSetupData.knx_ip = wgCfg.wireguard_knx_ip || '';
          this.wgSetupData.knx_port = wgCfg.wireguard_knx_port || 3671;
        }
      } catch (_) {}
    },

    wgLatencyColor() {
      if (this.wireguardLatencyMs === null) return 'bg-red-500';
      if (this.wireguardLatencyMs < 50) return 'bg-green-500';
      if (this.wireguardLatencyMs < 150) return 'bg-yellow-400';
      if (this.wireguardLatencyMs < 500) return 'bg-orange-500';
      return 'bg-red-500';
    },

    canWriteGA() {
      if (!this.wireguardEnabled) return true;
      return this.wireguardAllowedActions.includes('ga_rw');
    },

    wgActionTooltip(action) {
      if (!this.wireguardEnabled) return '';
      if (this.wireguardAllowedActions.includes(action)) return '';
      if (this.wireguardLatencyMs === null) return 'Keine Latenzmessung verfügbar';
      return `Latenz zu hoch (${this.wireguardLatencyMs} ms) — nicht verfügbar`;
    },

    async wgSetup() {
      this.wgSetupResult = '';
      this.wgSetupError = '';
      try {
        const res = await fetch('/api/wireguard/setup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.wgSetupData),
        });
        const data = await res.json();
        if (res.ok) {
          this.wireguardEnabled = true;
          this.wgSetupResult = data.server_public_key || 'OK';
        } else {
          this.wgSetupError = data.detail || 'Fehler';
        }
      } catch (e) {
        this.wgSetupError = 'Netzwerkfehler: ' + e.message;
      }
    },

    async wgTeardown() {
      if (!confirm('WireGuard-Tunnel abbauen?')) return;
      try {
        const res = await fetch('/api/wireguard/setup', { method: 'DELETE' });
        if (res.ok) {
          this.wireguardEnabled = false;
          this.wireguardLatencyMs = null;
          this.wireguardAllowedActions = ['monitor'];
          this.wireguardEtsPortActive = false;
        }
      } catch (_) {}
    },

    async wgToggleEts() {
      try {
        const res = await fetch('/api/wireguard/ets-access', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enable: !this.wireguardEtsPortActive }),
        });
        if (res.ok) {
          const data = await res.json();
          this.wireguardEtsPortActive = data.ets_port_active;
        }
      } catch (_) {}
    },

    async wgMeasureLatency() {
      try {
        const res = await fetch('/api/wireguard/latency-test', { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          this.wireguardLatencyMs = data.latency_ms;
          this.wireguardAllowedActions = data.allowed_actions;
        }
      } catch (_) {}
    },

    async wgDownloadPeerConfig() {
      const a = document.createElement('a');
      a.href = '/api/wireguard/peer-config';
      a.download = 'wg0_client.conf';
      a.click();
    },

    startEdit(type, key, field, current) {
      this.editingKey = `${type}|${key}|${field}`;
      this.editValue = current;
    },

    async saveEdit() {
      if (!this.editingKey) return;
      const parts = this.editingKey.split('|');
      const type = parts[0];
      const field = parts[parts.length - 1];
      const key = parts.slice(1, -1).join('|');
      this.editingKey = '';
      if (!this.annotations[type]) this.annotations[type] = {};
      if (!this.annotations[type][key]) this.annotations[type][key] = {};
      this.annotations[type][key][field] = this.editValue;
      this.annotations = { ...this.annotations };
      await fetch('/api/annotations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this.annotations),
      });
    },

    get busDevices() {
      const map = {};
      for (const e of this.liveLog) {
        if (!map[e.src]) map[e.src] = { individual_address: e.src, busName: e.device || '', count: 0, lastTs: e.ts, gas: [] };
        const d = map[e.src];
        d.count++;
        if (e.ts > d.lastTs) d.lastTs = e.ts;
        if (e.ga && !d.gas.includes(e.ga)) d.gas.push(e.ga);
        if (!d.busName && e.device) d.busName = e.device;
      }
      return Object.values(map)
        .map(d => ({ ...d, gas: d.gas.sort(),
          name: this.annotations.devices?.[d.individual_address]?.name ?? d.busName ?? '',
          description: this.annotations.devices?.[d.individual_address]?.description ?? '' }))
        .sort((a, b) => a.individual_address.localeCompare(b.individual_address));
    },

    get filteredBusDevices() {
      const q = this.deviceSearch.toLowerCase();
      if (!q) return this.busDevices;
      return this.busDevices.filter(d =>
        d.individual_address.includes(q) || d.name.toLowerCase().includes(q) ||
        (d.description || '').toLowerCase().includes(q));
    },

    get busGAs() {
      const map = {};
      for (const e of this.liveLog) {
        if (!map[e.ga]) map[e.ga] = { address: e.ga, busName: e.ga_name || '', lastValue: e.value, lastTs: e.ts, srcs: [] };
        const g = map[e.ga];
        if (!g.srcs.includes(e.src)) g.srcs.push(e.src);
        if (!g.busName && e.ga_name) g.busName = e.ga_name;
      }
      return Object.values(map)
        .map(g => ({ ...g, srcs: g.srcs.sort(),
          name: this.annotations.group_addresses?.[g.address]?.name ?? g.busName ?? '',
          description: this.annotations.group_addresses?.[g.address]?.description ?? '' }))
        .sort((a, b) => a.address.localeCompare(b.address));
    },

    get filteredBusGAs() {
      const q = this.gaSearch.toLowerCase();
      if (!q) return this.busGAs;
      return this.busGAs.filter(g =>
        g.address.includes(q) || g.name.toLowerCase().includes(q) ||
        (g.description || '').toLowerCase().includes(q));
    },

    connectWebSocket() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      this.ws = new WebSocket(`${protocol}//${location.host}/ws`);
      this.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'status') {
          this.wsStatus = msg.connected ? 'connected' : 'disconnected';
          if (msg.ip === 'remote') {
            this.remoteGatewayConnected = msg.connected;
          } else {
            this.gatewayIP = msg.ip || '';
            this.gatewayPort = msg.port || 3671;
          }
          this.gatewayLanguage = msg.language || 'de-DE';
        } else if (msg.type === 'snapshot') {
          this.currentValues = msg.values;
        } else if (msg.type === 'history') {
          this.liveLog = msg.entries;
          this._rebuildGAHistory(msg.entries);
        } else if (msg.type === 'telegram') {
          this.currentValues[msg.ga] = { value: msg.value, ts: msg.ts };
          this._pushGAHistory(msg.ga, msg.value, msg.ts);
          if (!this.liveLogPaused) {
            this.liveLog = [msg, ...this.liveLog].slice(0, 1000);
          }
        } else if (msg.type === 'wireguard_status') {
          this.wireguardLatencyMs = msg.latency_ms;
          this.wireguardPeerConnected = msg.peer_connected;
          this.wireguardAllowedActions = msg.allowed_actions;
        } else if (msg.type === 'scan_pa_found') {
          this.paScanFound = [...this.paScanFound, msg.address];
        } else if (msg.type === 'scan_pa_progress') {
          this.paScanProgress = msg.done;
          this.paScanTotal = msg.total;
        } else if (msg.type === 'scan_pa_complete') {
          this.paScanning = false;
          this.paScanProgress = msg.total;
          this.paScanTotal = msg.total;
          this.paScanDone = true;
          this.paScanCancelled = msg.cancelled || false;
          if (msg.found && msg.found.length > 0) this.paScanFound = msg.found;
        } else if (msg.type === 'scan_ga_progress') {
          this.gaScanProgress = msg.done;
          this.gaScanTotal = msg.total;
        } else if (msg.type === 'scan_ga_complete') {
          this.gaScanning = false;
          this.gaScanProgress = msg.total;
          this.gaScanTotal = msg.total;
          this.gaScanDone = true;
          this.gaScanCancelled = msg.cancelled || false;
        } else if (msg.type === 'telegram' && this.gaScanning) {
          if (msg.apci === 'GroupValueResponse') this.gaScanResponded++;
        }
      };
      this.ws.onclose = () => {
        this.wsStatus = 'disconnected';
        setTimeout(() => this.connectWebSocket(), 3000);
      };
      this.ws.onerror = () => { this.wsStatus = 'error'; };
    },

    skipToMonitor() {
      this.phase = 'result';
      this.activeTab = 'bus_monitor';
    },

    async loadRecentProjects() {
      try {
        const res = await fetch('/api/recent-projects');
        if (res.ok) this.recentProjects = await res.json();
      } catch (_) {}
    },

    async loadProjectNotes() {
      try {
        const res = await fetch('/api/recent-projects/notes');
        if (res.ok) this.projectNotes = await res.json();
      } catch (_) {}
    },

    async loadSelectedRecentProject() {
      if (!this.selectedRecentSlug) return;
      this.loading = true;
      this.error = '';
      try {
        const res = await fetch(`/api/recent-projects/${this.selectedRecentSlug}/data`);
        if (!res.ok) { this.error = 'Fehler beim Laden'; return; }
        this.project = await res.json();
        this.commGraphReady = false; this.commSelectedNode = null; if (this.commNetwork) { this.commNetwork.destroy(); this.commNetwork = null; }
        this.phase = 'result';
        this.activeTab = 'info';
        this.currentProjectSlug = this.selectedRecentSlug;
        this.selectedRecentSlug = null;
        this.loadRecentProjects();
      } catch (e) {
        this.error = 'Netzwerkfehler: ' + e.message;
      } finally {
        this.loading = false;
      }
    },

    async removeRecentProject(slug) {
      try {
        await fetch(`/api/recent-projects/${slug}`, { method: 'DELETE' });
        this.recentProjects = this.recentProjects.filter(p => p.slug !== slug);
        if (this.selectedRecentSlug === slug) this.selectedRecentSlug = null;
      } catch (_) {}
    },

    async exportRecentJson(proj) {
      try {
        const res = await fetch(`/api/recent-projects/${proj.slug}/data`);
        if (!res.ok) return;
        const data = await res.json();
        const safe = (proj.project_name || proj.filename).replace(/[^a-zA-Z0-9_\-]/g, '_');
        this._download(JSON.stringify(data, null, 2), `${safe}.json`, 'application/json');
      } catch (_) {}
    },

    downloadRecentKnxproj(proj) {
      if (!proj.knxproj_stored) {
        alert('.knxproj nicht verfügbar — bitte Datei erneut hochladen');
        return;
      }
      const a = document.createElement('a');
      a.href = `/api/recent-projects/${proj.slug}/knxproj`;
      a.download = proj.filename || `${proj.slug}.knxproj`;
      a.click();
    },

    async exportRecentXml(proj) {
      if (!proj.knxproj_stored) {
        alert('XML nicht verfügbar — bitte Datei erneut hochladen');
        return;
      }
      try {
        const res = await fetch(`/api/recent-projects/${proj.slug}/xml`);
        if (!res.ok) { alert('XML konnte nicht exportiert werden'); return; }
        const text = await res.text();
        const safe = (proj.project_name || proj.filename).replace(/[^a-zA-Z0-9_\-]/g, '_').replace(/\.knxproj$/i, '');
        this._download(text, `${safe}.xml`, 'application/xml;charset=utf-8');
      } catch (_) {}
    },

    openProjectNotes(proj) {
      this.notesModalSlug = proj.slug;
      this.notesModalTitle = proj.project_name || proj.filename;
      this.notesModalText = this.projectNotes[proj.slug] || '';
      this.notesModalOpen = true;
    },

    async saveProjectNotes() {
      try {
        await fetch(`/api/recent-projects/${this.notesModalSlug}/notes`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: this.notesModalText }),
        });
        this.projectNotes = { ...this.projectNotes, [this.notesModalSlug]: this.notesModalText };
        this.notesModalOpen = false;
      } catch (e) {
        alert('Fehler beim Speichern: ' + e.message);
      }
    },

    formatRecentDate(iso) {
      if (!iso) return '';
      const d = new Date(iso);
      return d.toLocaleDateString('de-DE', {day:'2-digit',month:'2-digit',year:'numeric'})
           + ' ' + d.toLocaleTimeString('de-DE', {hour:'2-digit',minute:'2-digit'});
    },

    async loadDemo() {
      this.loading = true;
      this.error = '';
      try {
        const res = await fetch('/api/demo');
        if (!res.ok) { this.error = 'Demo konnte nicht geladen werden'; return; }
        this.project = await res.json();
        this.commGraphReady = false; this.commSelectedNode = null; if (this.commNetwork) { this.commNetwork.destroy(); this.commNetwork = null; }
        this.phase = 'result';
        this.activeTab = 'info';
        this.newLlmChat();
      } catch (e) {
        this.error = 'Netzwerkfehler: ' + e.message;
      } finally {
        this.loading = false;
      }
    },

    async loadLastProject() {
      this.loading = true;
      this.error = '';
      try {
        const res = await fetch('/api/last-project/data');
        if (!res.ok) { this.error = 'Fehler beim Laden des letzten Projekts'; return; }
        this.project = await res.json();
        this.commGraphReady = false; this.commSelectedNode = null; if (this.commNetwork) { this.commNetwork.destroy(); this.commNetwork = null; }
        this.phase = 'result';
        this.activeTab = 'info';
        this.newLlmChat();
      } catch (e) {
        this.error = 'Netzwerkfehler: ' + e.message;
      } finally {
        this.loading = false;
      }
    },

    gaWriteOptions(ga) {
      if (!ga.dpt || !ga.dpt.main) return null;
      const main = Number(ga.dpt.main);
      const sub  = Number(ga.dpt.sub ?? 0);
      if (main !== 1) return null;
      // DPT 1.x — two-state binary values
      const labels = {
        8:  ['Aufwärts', 'Abwärts'],   // 1.008 Up/Down
        9:  ['Öffnen', 'Schließen'],    // 1.009 Open/Close
        10: ['Start', 'Stop'],          // 1.010 Start/Stop
        19: ['Inaktiv', 'Aktiv'],       // 1.019 Inactive/Active
        21: ['Kein Reset', 'Reset'],    // 1.021 Reset
        22: ['Kein Erkennen', 'Erkennen'], // 1.022 Acknowledge
      };
      const pair = labels[sub] ?? ['Aus', 'Ein'];
      return [
        { label: pair[0], value: '0' },
        { label: pair[1], value: '1' },
      ];
    },

    renderMarkdown(text) {
      if (!text) return '';
      if (typeof marked === 'undefined') return text;
      try {
        return marked.parse(text, { breaks: true, gfm: true });
      } catch (e) {
        return text;
      }
    },

    gaIsReadable(ga) {
      if (!this.project) return false;
      const cos = this.project.communication_objects ?? {};
      return (ga.communication_object_ids ?? []).some(id => cos[id]?.flags?.read === true);
    },

    async writeGA(ga) {
      const value = this.gaWriteValues[ga];
      if (value === undefined || value === '') return;
      try {
        const res = await fetch('/api/ga/write', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ga, value }),
        });
        if (!res.ok) {
          const err = await res.json();
          alert('Fehler: ' + (err.detail || 'Unbekannter Fehler'));
        }
      } catch (e) {
        alert('Netzwerkfehler: ' + e.message);
      }
    },

    async readGA(ga) {
      try {
        await fetch('/api/ga/read', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ga }),
        });
      } catch (e) {
        alert('Netzwerkfehler: ' + e.message);
      }
    },

    async readAllGAs() {
      this.readingAll = true;
      try {
        const res = await fetch('/api/ga/read-all', { method: 'POST' });
        if (!res.ok) {
          const err = await res.json();
          alert('Fehler: ' + (err.detail || 'Unbekannter Fehler'));
        }
      } catch (e) {
        alert('Netzwerkfehler: ' + e.message);
      } finally {
        // Keep button disabled for ~3 s to avoid double-clicks while responses arrive
        setTimeout(() => { this.readingAll = false; }, 3000);
      }
    },

    async loadLlmConfig() {
      try {
        const res = await fetch('/api/llm/config');
        if (res.ok) {
          const cfg = await res.json();
          this.llmConfigured = cfg.configured;
          this.llmModel = cfg.model;
          if (cfg.local_url) this.llmLocalUrl = cfg.local_url;
          this.llmLocalTokenSet = !!cfg.local_token_set;
          const isLocal = cfg.model === 'local-model' || cfg.model.startsWith('lm:');
          this.llmProvider = isLocal ? 'local' : 'openrouter';
        }
      } catch (_) {}
      await this.loadLmStudioModels();
    },

    async loadLmStudioModels() {
      try {
        const res = await fetch('/api/llm/lmstudio/models');
        if (res.ok) {
          const data = await res.json();
          this.lmStudioAvailable = data.available;
          this.lmStudioModels = data.models.length ? data.models : ['local-model'];
        }
      } catch (_) {
        this.lmStudioAvailable = false;
      }
    },

    onProviderChange() {
      if (this.llmProvider === 'local') {
        const isLocalVal = this.llmModel === 'local-model' || this.llmModel.startsWith('lm:');
        if (!isLocalVal) {
          // Erstes echtes Modell vorwählen; 'local-model' als Fallback
          const real = this.lmStudioModels.find((m) => m !== 'local-model');
          this.llmModel = real ? 'lm:' + real : 'local-model';
        }
      } else if (this.llmModel === 'local-model' || this.llmModel.startsWith('lm:')) {
        this.llmModel = 'z-ai/glm-5';
      }
    },

    async saveLlmConfig() {
      try {
        const body = { model: this.llmModel };
        if (this.llmProvider === 'openrouter' && this.llmApiKey) {
          body.api_key = this.llmApiKey;
        }
        if (this.llmProvider === 'local') {
          body.local_url = this.llmLocalUrl;
          if (this.llmLocalToken) body.local_token = this.llmLocalToken;
        }
        const res = await fetch('/api/llm/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (res.ok) {
          const isLocal = this.llmProvider === 'local';
          this.llmConfigured = !!this.llmApiKey || isLocal;
          this.llmApiKey = '';
          if (this.llmLocalToken) this.llmLocalTokenSet = true;
          this.llmLocalToken = '';
          this.showGatewayConfig = false;
        }
      } catch (e) {
        alert('Fehler beim Speichern: ' + e.message);
      }
    },

    // Lokale URL/Token speichern und Modell-Liste neu laden (Verbindung testen)
    async testLocalLlm() {
      try {
        const body = { local_url: this.llmLocalUrl };
        if (this.llmLocalToken) body.local_token = this.llmLocalToken;
        await fetch('/api/llm/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (this.llmLocalToken) this.llmLocalTokenSet = true;
        this.llmLocalToken = '';
      } catch (_) {}
      await this.loadLmStudioModels();
    },

    setLlmQuestion(question) {
      this.llmQuestion = question;
      this.analyzeLlm();
    },

    async analyzeLlm() {
      if (!this.llmQuestion.trim()) return;

      this.llmLoading = true;
      this.llmError = '';
      this.llmResponse = '';
      this.llmReasoning = '';

      // Store current question
      const currentQuestion = this.llmQuestion.trim();
      
      try {
        const res = await fetch('/api/llm/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            question: currentQuestion,
            history: this.llmMessages,
            include_bus_activity: this.llmIncludeBus,
            bus_limit: this.llmBusLimit,
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          this.llmError = err.detail || 'Fehler bei der Anfrage';
          return;
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          for (const line of decoder.decode(value).split('\n')) {
            if (!line.startsWith('data: ') || line === 'data: [DONE]') continue;
            try {
              const d = JSON.parse(line.slice(6));
              if (d.error) { this.llmError = d.error; break; }
              const delta = d.choices?.[0]?.delta ?? {};
              this.llmReasoning += delta.reasoning ?? '';
              this.llmResponse  += delta.content  ?? '';
            } catch (_) {}
          }
        }
        
        // Add Q&A to history and clear streaming state
        this.llmMessages.push(
          { role: 'user', content: currentQuestion },
          { role: 'assistant', content: this.llmResponse }
        );
        this.llmResponse = '';
        this.llmReasoning = '';
        this.llmQuestion = '';
        
      } catch (e) {
        this.llmError = 'Netzwerkfehler: ' + e.message;
      } finally {
        this.llmLoading = false;
      }
    },

    newLlmChat() {
      this.llmMessages = [];
      this.llmResponse = '';
      this.llmReasoning = '';
      this.llmError = '';
      this.llmQuestion = '';
    },

    exportLlm() {
      const projectName = this.project?.info?.name ?? 'KNX-Projekt';
      const lines = [
        `# KI-Analyse: ${projectName}`,
        '',
        `**Datum:** ${new Date().toLocaleString('de-DE')}`,
        '',
        '---',
        '',
      ];
      
      // Export entire conversation history
      for (const msg of this.llmMessages) {
        if (msg.role === 'user') {
          lines.push(`## Frage`, '', msg.content, '');
        } else {
          lines.push('## Antwort', '', msg.content, '', '---', '');
        }
      }
      
      const safe = projectName.replace(/[^a-zA-Z0-9_-]/g, '_');
      this._download(lines.join('\n'), `ki_analyse_${safe}.md`, 'text/markdown;charset=utf-8');
    },

    computeProjectDiff(projA, projB) {
      const gasA = {}, gasB = {};
      for (const ga of Object.values(projA.group_addresses ?? {})) gasA[ga.address] = ga;
      for (const ga of Object.values(projB.group_addresses ?? {})) gasB[ga.address] = ga;
      const gaAdded = [], gaRemoved = [], gaChanged = [];
      for (const addr of new Set([...Object.keys(gasA), ...Object.keys(gasB)])) {
        if (!gasA[addr]) { gaAdded.push(gasB[addr]); continue; }
        if (!gasB[addr]) { gaRemoved.push(gasA[addr]); continue; }
        const a = gasA[addr], b = gasB[addr];
        const dptA = a.dpt ? this._dptStr(a.dpt) : '';
        const dptB = b.dpt ? this._dptStr(b.dpt) : '';
        if (a.name !== b.name || dptA !== dptB)
          gaChanged.push({ address: addr, nameA: a.name, nameB: b.name, dptA, dptB,
            critical: dptA !== dptB && dptA !== '' && dptB !== '' });
      }
      const devsA = projA.devices ?? {}, devsB = projB.devices ?? {};
      const devAdded = [], devRemoved = [], devChanged = [];
      for (const addr of new Set([...Object.keys(devsA), ...Object.keys(devsB)])) {
        if (!devsA[addr]) { devAdded.push({ ...devsB[addr], individual_address: addr }); continue; }
        if (!devsB[addr]) { devRemoved.push({ ...devsA[addr], individual_address: addr }); continue; }
        if (devsA[addr].name !== devsB[addr].name)
          devChanged.push({ individual_address: addr, nameA: devsA[addr].name, nameB: devsB[addr].name });
      }
      return { ga: { added: gaAdded, removed: gaRemoved, changed: gaChanged },
               devices: { added: devAdded, removed: devRemoved, changed: devChanged } };
    },

    buildDiffSummary(diff, projA, projB) {
      const nameA = projA?.info?.name ?? 'Projekt A';
      const nameB = projB?.info?.name ?? 'Projekt B';
      const lines = [`Vergleich: "${nameA}" vs "${nameB}"`, '',
        `GRUPPENADRESSEN: Neu (${diff.ga.added.length}), Entfernt (${diff.ga.removed.length}), Geändert (${diff.ga.changed.length})`];
      for (const ga of diff.ga.added)
        lines.push(`  + ${ga.address}: ${ga.name}${ga.dpt ? ' [DPT ' + this._dptStr(ga.dpt) + ']' : ''}`);
      for (const ga of diff.ga.removed) lines.push(`  - ${ga.address}: ${ga.name}`);
      for (const c of diff.ga.changed) {
        if (c.dptA !== c.dptB) lines.push(`  ~ ${c.address}: DPT ${c.dptA||'–'} → ${c.dptB||'–'}${c.critical ? ' [KRITISCH]' : ''}`);
        if (c.nameA !== c.nameB) lines.push(`  ~ ${c.address}: "${c.nameA}" → "${c.nameB}"`);
      }
      lines.push('', `GERÄTE: Neu (${diff.devices.added.length}), Entfernt (${diff.devices.removed.length}), Geändert (${diff.devices.changed.length})`);
      for (const d of diff.devices.added) lines.push(`  + ${d.individual_address}: ${d.name}`);
      for (const d of diff.devices.removed) lines.push(`  - ${d.individual_address}: ${d.name}`);
      for (const c of diff.devices.changed) lines.push(`  ~ ${c.individual_address}: "${c.nameA}" → "${c.nameB}"`);
      return lines.join('\n');
    },

    async loadCompareProject() {
      if (!this.compareSlug) return;
      this.compareLoading = true; this.compareError = ''; this.compareDiff = null;
      this.compareProject = null; this.compareLlmResponse = ''; this.compareLlmReasoning = '';
      try {
        const res = await fetch(`/api/recent-projects/${encodeURIComponent(this.compareSlug)}/raw`);
        if (!res.ok) { this.compareError = 'Projekt konnte nicht geladen werden'; return; }
        this.compareProject = await res.json();
        this.compareDiff = this.computeProjectDiff(this.project, this.compareProject);
      } catch (e) { this.compareError = 'Netzwerkfehler: ' + e.message; }
      finally { this.compareLoading = false; }
    },

    async analyzeDiff() {
      if (!this.compareDiff) return;
      this.compareLlmLoading = true; this.compareLlmError = '';
      this.compareLlmResponse = ''; this.compareLlmReasoning = '';
      const nameA = this.project?.info?.name ?? 'Projekt A';
      const nameB = this.compareProject?.info?.name ?? 'Projekt B';
      try {
        const res = await fetch('/api/llm/compare', { method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ diff_text: this.buildDiffSummary(this.compareDiff, this.project, this.compareProject), name_a: nameA, name_b: nameB }) });
        if (!res.ok) { const err = await res.json(); this.compareLlmError = err.detail || 'Fehler'; return; }
        const reader = res.body.getReader(); const decoder = new TextDecoder();
        while (true) {
          const { done, value } = await reader.read(); if (done) break;
          for (const line of decoder.decode(value).split('\n')) {
            if (!line.startsWith('data: ') || line === 'data: [DONE]') continue;
            try { const d = JSON.parse(line.slice(6)); if (d.error) { this.compareLlmError = d.error; break; }
              const delta = d.choices?.[0]?.delta ?? {};
              this.compareLlmReasoning += delta.reasoning ?? ''; this.compareLlmResponse += delta.content ?? '';
            } catch (_) {}
          }
        }
      } catch (e) { this.compareLlmError = 'Netzwerkfehler: ' + e.message; }
      finally { this.compareLlmLoading = false; }
    },

    exportCompareDiff() {
      const nameA = this.project?.info?.name ?? 'Projekt A';
      const nameB = this.compareProject?.info?.name ?? 'Projekt B';
      const lines = [`# Projektvergleich: ${nameA} vs ${nameB}`, ''];
      // Geräte
      lines.push('## Geräte', '');
      if (this.compareDiff.devices.added.length) {
        lines.push('### Neu hinzugefügt');
        for (const d of this.compareDiff.devices.added) lines.push(`- + ${d.individual_address}: ${d.name}`);
        lines.push('');
      }
      if (this.compareDiff.devices.removed.length) {
        lines.push('### Entfernt');
        for (const d of this.compareDiff.devices.removed) lines.push(`- - ${d.individual_address}: ${d.name}`);
        lines.push('');
      }
      if (this.compareDiff.devices.changed.length) {
        lines.push('### Geändert');
        for (const c of this.compareDiff.devices.changed) lines.push(`- ~ ${c.individual_address}: "${c.nameA}" → "${c.nameB}"`);
        lines.push('');
      }
      // Gruppenadressen
      lines.push('## Gruppenadressen', '');
      if (this.compareDiff.ga.added.length) {
        lines.push('### Neu hinzugefügt');
        for (const ga of this.compareDiff.ga.added) lines.push(`- + ${ga.address}: ${ga.name}${ga.dpt ? ' [DPT ' + this._dptStr(ga.dpt) + ']' : ''}`);
        lines.push('');
      }
      if (this.compareDiff.ga.removed.length) {
        lines.push('### Entfernt');
        for (const ga of this.compareDiff.ga.removed) lines.push(`- - ${ga.address}: ${ga.name}`);
        lines.push('');
      }
      if (this.compareDiff.ga.changed.length) {
        lines.push('### Geändert');
        for (const c of this.compareDiff.ga.changed) {
          if (c.dptA !== c.dptB) lines.push(`- ${c.critical ? '⚠️ KRITISCH ' : ''}~ ${c.address}: DPT ${c.dptA||'–'} → ${c.dptB||'–'}`);
          if (c.nameA !== c.nameB) lines.push(`- ~ ${c.address}: "${c.nameA}" → "${c.nameB}"`);
        }
        lines.push('');
      }
      if (this.compareLlmResponse) {
        lines.push('---', '', '## KI-Analyse', '', this.compareLlmResponse);
        if (this.compareLlmReasoning) lines.push('', '### Denkprozess', '', this.compareLlmReasoning);
      }
      const safeA = nameA.replace(/[^a-zA-Z0-9_-]/g, '_');
      const safeB = nameB.replace(/[^a-zA-Z0-9_-]/g, '_');
      this._download(lines.join('\n'), `vergleich_${safeA}_vs_${safeB}.md`, 'text/markdown;charset=utf-8');
    },

    async saveGatewayConfig() {
      this.gatewayError = '';
      try {
        const payload = { language: this.gatewayLanguage, connection_type: this.connectionType };
        if (this.connectionType === 'local') {
          payload.ip = this.gatewayIP;
          payload.port = this.gatewayPort;
        }
        const res = await fetch('/api/gateway', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok) this.showGatewayConfig = false;
        else this.gatewayError = 'Fehler beim Speichern';
      } catch (e) {
        this.gatewayError = 'Netzwerkfehler: ' + e.message;
      }
    },

    async copyToken() {
      try {
        await navigator.clipboard.writeText(this.remoteGatewayToken);
        this.tokenCopied = true;
        setTimeout(() => { this.tokenCopied = false; }, 2000);
      } catch (_) {}
    },

    get visibleTabs() {
      return this.tabs.filter(tab => {
        if (tab.id === 'functions') return this.project && Object.keys(this.project.functions ?? {}).length > 0;
        if (tab.id === 'communication') return !!this.project;
        if (tab.id === 'bus_monitor') return !this.publicMode;
        if (tab.id === 'bus_scan') return !this.publicMode;
        if (tab.id === 'ki_analyse') return !this.publicMode && this.llmConfigured && !!this.project;
        if (tab.id === 'compare') return !this.publicMode && this.recentProjects.length > 1 && !!this.project;
        if (tab.id === 'snapshots') return !this.publicMode && !!this.project;
        return true;
      });
    },

    get _visibleToolTabs() {
      return this.visibleTabs.filter(t => this.toolsGroupIds.includes(t.id));
    },

    // If only one tool tab is visible (e.g. public mode shows just "Graph"),
    // promote it back to the main bar so the dropdown isn't a 1-item menu.
    get mainTabs() {
      if (this._visibleToolTabs.length <= 1) return this.visibleTabs;
      return this.visibleTabs.filter(t => !this.toolsGroupIds.includes(t.id));
    },

    get toolsTabs() {
      return this._visibleToolTabs.length <= 1 ? [] : this._visibleToolTabs;
    },

    get isToolsActive() {
      return this.toolsTabs.some(t => t.id === this.activeTab);
    },

    get activeToolLabel() {
      const t = this.toolsTabs.find(t => t.id === this.activeTab);
      return t ? t.label : '';
    },

    async scanProgMode() {
      this.progModeLoading = true;
      this.progModeError = '';
      this.progModeResults = [];
      this.progModeScanned = false;
      try {
        const res = await fetch('/api/bus/programming-mode?timeout=' + this.progModeTimeout);
        if (res.ok) { const d = await res.json(); this.progModeResults = d.addresses; this.progModeScanned = true; }
        else { const e = await res.json(); this.progModeError = e.detail || 'Fehler'; }
      } catch (e) { this.progModeError = String(e); }
      this.progModeLoading = false;
    },

    async loadGatewayDescription() {
      this.gatewayDescLoading = true;
      this.gatewayDescError = '';
      this.gatewayDescription = null;
      try {
        const res = await fetch('/api/gateway/description');
        if (res.ok) this.gatewayDescription = await res.json();
        else { const e = await res.json(); this.gatewayDescError = e.detail || 'Fehler'; }
      } catch (e) { this.gatewayDescError = String(e); }
      this.gatewayDescLoading = false;
    },

    async startPaScan() {
      this.paScanFound = [];
      this.paScanProgress = 0;
      this.paScanTotal = 0;
      this.paScanDone = false;
      this.paScanCancelled = false;
      this.paScanning = true;
      const body = { timeout_ms: Number(this.scanTimeoutMs) };
      if (this.scanArea !== '') body.area = Number(this.scanArea);
      if (this.scanLine !== '') body.line = Number(this.scanLine);
      if (this.scanDevice !== '') body.device = Number(this.scanDevice);
      try {
        const res = await fetch('/api/bus/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!res.ok) { const e = await res.json(); this.paScanning = false; alert('PA-Scan Fehler: ' + (e.detail || res.status)); }
        else { const d = await res.json(); this.paScanTotal = d.count; }
      } catch (e) { this.paScanning = false; alert('PA-Scan Fehler: ' + e); }
    },

    async cancelPaScan() {
      await fetch('/api/bus/scan/cancel', { method: 'POST' });
    },

    async startGaScan() {
      this.gaScanProgress = 0;
      this.gaScanTotal = 0;
      this.gaScanDone = false;
      this.gaScanCancelled = false;
      this.gaScanResponded = 0;
      this.gaScanning = true;
      try {
        const res = await fetch('/api/ga/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ start: this.gaScanStart, end: this.gaScanEnd, delay_ms: Number(this.gaScanDelayMs) }) });
        if (!res.ok) { const e = await res.json(); this.gaScanning = false; alert('GA-Scan Fehler: ' + (e.detail || res.status)); }
        else { const d = await res.json(); this.gaScanTotal = d.count; }
      } catch (e) { this.gaScanning = false; alert('GA-Scan Fehler: ' + e); }
    },

    async cancelGaScan() {
      await fetch('/api/ga/scan/cancel', { method: 'POST' });
    },

    async loadDeviceProperties(addr) {
      this.devicePropsAddr = addr;
      this.devicePropsData = null;
      this.devicePropsLoading = true;
      this.devicePropsError = '';
      this.devicePropsModal = true;
      try {
        const res = await fetch('/api/device/' + encodeURIComponent(addr) + '/properties');
        if (res.ok) this.devicePropsData = await res.json();
        else { const e = await res.json(); this.devicePropsError = e.detail || 'Fehler'; }
      } catch (e) { this.devicePropsError = String(e); }
      this.devicePropsLoading = false;
    },

    get filteredLiveLog() {
      if (!this.liveLogFilter) return this.liveLog;
      const f = this.liveLogFilter.toLowerCase();
      return this.liveLog.filter(e =>
        e.ga.includes(f) || (e.ga_name || '').toLowerCase().includes(f) ||
        (e.device || '').toLowerCase().includes(f) || (e.value || '').toLowerCase().includes(f) ||
        e.src.includes(f)
      );
    },

    onFileChange(event) {
      const file = event.target.files[0];
      if (file) this.selectedFile = file;
    },

    onDrop(event) {
      const file = event.dataTransfer.files[0];
      if (file) this.selectedFile = file;
    },

    async parseProject() {
      if (!this.selectedFile) return;
      this.loading = true;
      this.error = '';
      const form = new FormData();
      form.append('file', this.selectedFile);
      form.append('password', this.password);
      form.append('language', this.gatewayLanguage);
      try {
        const res = await fetch('/api/parse', { method: 'POST', body: form });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          const sizeMb = (this.selectedFile.size / (1024 * 1024)).toFixed(1);
          if (res.status === 413) {
            this.error = `Datei zu groß (${sizeMb} MB). Der Server oder ein vorgeschalteter Proxy lehnt sie ab.`;
          } else {
            this.error = (err.detail ?? 'Unbekannter Fehler') + ` (HTTP ${res.status}, Datei: ${sizeMb} MB)`;
          }
          return;
        }
        this.project = await res.json();
        this.commGraphReady = false; this.commSelectedNode = null; if (this.commNetwork) { this.commNetwork.destroy(); this.commNetwork = null; }
        this.phase = 'result';
        this.currentProjectSlug = null;
        this.loadRecentProjects();
        this.newLlmChat();
      } catch (e) {
        this.error = 'Netzwerkfehler: ' + e.message;
      } finally {
        this.loading = false;
      }
    },

    reset() {
      this.phase = 'upload';
      this.project = null;
      this.commGraphReady = false; this.commSelectedNode = null; if (this.commNetwork) { this.commNetwork.destroy(); this.commNetwork = null; }
      this.selectedFile = null;
      this.error = '';
      this.expandedTopology = new Set();
      this.expandedCODevices = new Set();
      this.highlightedCO = null;
      this.deviceSearch = '';
      this.gaSearch = '';
      this.coSearch = '';
      this.newLlmChat();
    },

    _b64ToHex(s) {
      if (!s) return s;
      try {
        const bin = atob(s);
        return Array.from(bin).map(c => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()).join(' ');
      } catch { return s; }
    },

    _mdEsc(s) {
      return String(s ?? '').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
    },

    _dptStr(dpt) {
      if (!dpt) return '—';
      return dpt.sub != null ? `${dpt.main}.${String(dpt.sub).padStart(3,'0')}` : String(dpt.main);
    },

    _download(content, filename, type) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    },

    exportMarkdown() {
      if (!this.project) { this._exportBusMarkdown(); return; }
      const e = s => this._mdEsc(s);
      const d = dpt => this._dptStr(dpt);
      const lines = [];

      lines.push(`# ${e(this.projectName)}`, '');

      lines.push('## Projektinformationen', '');
      for (const [key, val] of this.infoRows) lines.push(`- **${e(key)}:** ${e(val)}`);
      lines.push('');

      const notes = this.currentProjectSlug ? this.projectNotes[this.currentProjectSlug] : null;
      if (notes) lines.push('## Notizen', '', notes, '');

      lines.push('## Geräte', '');
      lines.push('| Adresse | Name | Hersteller | Bestellnr. | Applikation |');
      lines.push('|---------|------|------------|------------|-------------|');
      for (const dev of this.allDevices)
        lines.push(`| ${e(dev.individual_address)} | ${e(dev.name)} | ${e(dev.manufacturer_name)} | ${e(dev.order_number)} | ${e(dev.application)} |`);
      lines.push('');

      lines.push('## Gruppenadressen', '');
      lines.push('| Adresse | Name | DPT | Beschreibung | Verknüpfte KOs |');
      lines.push('|---------|------|-----|--------------|----------------|');
      for (const ga of this.allGAs) {
        const cos = (ga.communication_object_ids ?? []).map(id => {
          const co = this.project?.communication_objects?.[id];
          return co ? `${co.device_address} #${co.number}` : null;
        }).filter(Boolean).join(', ');
        lines.push(`| ${e(ga.address)} | ${e(ga.name)} | ${e(d(ga.dpt))} | ${e(ga.description)} | ${e(cos || '—')} |`);
      }
      lines.push('');

      lines.push('## Kommunikationsobjekte', '');
      for (const group of this.cosByDevice) {
        lines.push(`### ${e(group.addr)} – ${e(group.deviceName)}`, '');
        lines.push('| KO-Nr. | Name | DPT | Flags | Gruppenadressen |');
        lines.push('|--------|------|-----|-------|-----------------|');
        for (const co of group.cos) {
          const gaStr = this.exportDetailed
            ? (co.group_address_links ?? []).map(addr => {
                const ga = this.gaByAddress[addr];
                return ga ? (ga.description ? `${addr} ${ga.name} — ${ga.description}` : `${addr} ${ga.name}`) : addr;
              }).join('; ') || '—'
            : (co.group_address_links ?? []).join(', ') || '—';
          lines.push(`| ${co.number} | ${e(co.name)} | ${e(d(co.dpts?.[0]))} | ${e(this.flagString(co))} | ${e(gaStr)} |`);
        }
        lines.push('');
      }

      lines.push('## Topologie', '');
      for (const [areaId, area] of Object.entries(this.project?.topology ?? {})) {
        lines.push(`### Bereich ${e(areaId)} – ${e(area.name)}`, '');
        for (const [lineId, line] of Object.entries(area.lines ?? {})) {
          lines.push(`#### Linie ${e(areaId)}.${e(lineId)} – ${e(line.name)}`, '');
          for (const addr of (line.devices ?? [])) {
            const dev = this.project?.devices?.[addr];
            lines.push(`- \`${e(addr)}\` ${e(dev?.name ?? '')}`);
          }
          lines.push('');
        }
      }

      const fns = Object.values(this.project?.functions ?? {});
      if (fns.length) {
        lines.push('## Funktionen', '');
        lines.push('| Name | Typ | Gruppenadressen |');
        lines.push('|------|-----|-----------------|');
        for (const fn of fns) {
          const gas = Object.values(fn.group_addresses ?? {}).map(r => r.address).join(', ');
          lines.push(`| ${e(fn.name)} | ${e(fn.function_type)} | ${e(gas || '—')} |`);
        }
        lines.push('');
      }

      // KNX Security
      const sec = this.project?._security;
      if (sec?.devices?.length || Object.keys(sec?.ga_keys ?? {}).length || (!this.publicMode && sec?.ets_certificates?.length)) {
        lines.push('## KNX Data Secure', '');

        if (sec.devices?.length) {
          lines.push('### Gerätesicherheit', '');
          for (const dev of sec.devices) {
            lines.push(`#### \`${e(dev.address)}\` – ${e(dev.name || '—')}`, '');
            if (dev.ip_address != null)           lines.push(`- **IP-Adresse:** ${e(dev.ip_address)}`);
            if (dev.mac_address != null)          lines.push(`- **MAC-Adresse:** ${e(dev.mac_address)}`);
            if (dev.tool_key != null)             lines.push(`- **Tool Key:** \`${e(this._b64ToHex(dev.tool_key))}\``);
            if (dev.device_auth_code != null)     lines.push(`- **Auth Code:** \`${e(dev.device_auth_code)}\``);
            if (dev.device_mgmt_password != null) lines.push(`- **Management Passwort:** \`${e(dev.device_mgmt_password)}\``);
            if (dev.sequence_number != null)      lines.push(`- **Sequenznummer:** ${e(String(dev.sequence_number))}`);
            for (const [idx, bi] of (dev.bus_interfaces ?? []).entries())
              lines.push(`- **Bus-IF ${idx + 1}:** \`${e(bi.password)}\``);
            lines.push('');
          }
        }

        const gaKeys = Object.entries(sec.ga_keys ?? {});
        if (gaKeys.length) {
          lines.push('### Gruppen-Schlüssel', '');
          lines.push('| GA | Schlüssel |');
          lines.push('|----|-----------|');
          for (const [ga, key] of gaKeys)
            lines.push(`| \`${e(ga)}\` | \`${e(this._b64ToHex(key))}\` |`);
          lines.push('');
        }

        if (!this.publicMode && sec.ets_certificates?.length) {
          lines.push('### ETS Lizenzzertifikat', '');
          for (const cert of sec.ets_certificates) {
            for (const [label, field, hex] of [['Kunde','CUSTOMER',false],['Lizenznummer','NUMBER',false],['Lizenztyp','LICENSE',false],['Datum','DATE',false],['Public Key','PUBLICKEY',true],['Root Cert','ROOTCERT',true],['Signatur','SIGN',true]])
              if (cert[field] != null) lines.push(`- **${label}:** \`${e(hex ? this._b64ToHex(cert[field]) : cert[field])}\``);
            lines.push('');
          }
        }
      }

      const safe = this.projectName.replace(/[^a-zA-Z0-9_\-]/g, '_');
      this._download(lines.join('\n'), `${safe}.md`, 'text/markdown;charset=utf-8');
    },

    _exportBusMarkdown() {
      const e = s => this._mdEsc(s);
      const lines = [
        '# KNX Bus-Dokumentation',
        `*Erstellt: ${new Date().toLocaleString('de-DE')}*`, '',
        '## Geräte', '',
        '| PA | Name | Beschreibung | Telegramme | Letztes Telegramm | GAs |',
        '|----|------|--------------|:----------:|-------------------|-----|',
      ];
      for (const d of this.busDevices)
        lines.push(`| ${e(d.individual_address)} | ${e(d.name)} | ${e(d.description)} | ${d.count} | ${e(d.lastTs)} | ${e(d.gas.join(', '))} |`);
      lines.push('', '## Gruppenadressen', '',
        '| Adresse | Name | Beschreibung | Letzter Wert | Zeitstempel | Quell-PAs |',
        '|---------|------|--------------|--------------|-------------|-----------|');
      for (const g of this.busGAs)
        lines.push(`| ${e(g.address)} | ${e(g.name)} | ${e(g.description)} | ${e(g.lastValue)} | ${e(g.lastTs)} | ${e(g.srcs.join(', '))} |`);
      lines.push('');
      this._download(lines.join('\n'), 'knx_bus_dokumentation.md', 'text/markdown;charset=utf-8');
    },

    exportPDF() {
      if (!this.project) { this._exportBusPDF(); return; }
      const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const d = dpt => this._dptStr(dpt);

      const css = `
        body{font-family:Arial,sans-serif;font-size:9pt;color:#1f2937;margin:15mm}
        h1{font-size:16pt;border-bottom:2px solid #2563eb;padding-bottom:4px;margin-bottom:12px}
        h2{font-size:12pt;color:#1d4ed8;margin-top:20px;border-bottom:1px solid #d1d5db;page-break-after:avoid}
        h3{font-size:10pt;color:#374151;margin:10px 0 4px}
        h4{font-size:9pt;color:#1d4ed8;margin:8px 0 2px;font-weight:600}
        table{width:100%;border-collapse:collapse;margin:6px 0;font-size:8pt}
        th{background:#f3f4f6;text-align:left;padding:4px 6px;border:1px solid #d1d5db;font-weight:600}
        td{padding:3px 6px;border:1px solid #d1d5db;vertical-align:top}
        tr:nth-child(even) td{background:#f9fafb}
        .dh td{background:#dbeafe;font-weight:600}
        .mono{font-family:monospace}
        dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;margin:6px 0}
        dt{font-weight:600;color:#6b7280}
        @media print{h2{page-break-before:auto}}`;

      let html = `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8">
        <title>${esc(this.projectName)}</title><style>${css}</style></head><body>
        <h1>${esc(this.projectName)}</h1>`;

      // Info
      html += '<h2>Projektinformationen</h2><dl>';
      for (const [key, val] of this.infoRows)
        html += `<dt>${esc(key)}</dt><dd>${esc(val)}</dd>`;
      html += '</dl>';

      const notes = this.currentProjectSlug ? this.projectNotes[this.currentProjectSlug] : null;
      if (notes) html += `<h2>Notizen</h2><div style="font-size:9pt;line-height:1.5">${this.renderMarkdown(notes)}</div>`;

      // Devices
      html += '<h2>Geräte</h2><table><thead><tr><th>Adresse</th><th>Name</th><th>Hersteller</th><th>Bestellnr.</th><th>Applikation</th></tr></thead><tbody>';
      for (const dev of this.allDevices)
        html += `<tr><td class="mono">${esc(dev.individual_address)}</td><td>${esc(dev.name)}</td><td>${esc(dev.manufacturer_name)}</td><td>${esc(dev.order_number)}</td><td>${esc(dev.application)}</td></tr>`;
      html += '</tbody></table>';

      // Group addresses
      html += '<h2>Gruppenadressen</h2><table><thead><tr><th>Adresse</th><th>Name</th><th>DPT</th><th>Beschreibung</th><th>Verknüpfte KOs</th></tr></thead><tbody>';
      for (const ga of this.allGAs) {
        const cos = (ga.communication_object_ids ?? []).map(id => {
          const co = this.project?.communication_objects?.[id];
          return co ? `${co.device_address} #${co.number}` : null;
        }).filter(Boolean).join(', ');
        html += `<tr><td class="mono">${esc(ga.address)}</td><td>${esc(ga.name)}</td><td class="mono">${esc(d(ga.dpt))}</td><td>${esc(ga.description)}</td><td class="mono">${esc(cos||'—')}</td></tr>`;
      }
      html += '</tbody></table>';

      // Communication objects
      html += '<h2>Kommunikationsobjekte</h2><table><thead><tr><th>KO-Nr.</th><th>Name</th><th>DPT</th><th>Flags</th><th>Gruppenadressen</th></tr></thead><tbody>';
      for (const group of this.cosByDevice) {
        html += `<tr class="dh"><td colspan="5">${esc(group.addr)} – ${esc(group.deviceName)}</td></tr>`;
        for (const co of group.cos) {
          const gaCell = this.exportDetailed
            ? (co.group_address_links ?? []).map(addr => {
                const ga = this.gaByAddress[addr];
                if (!ga) return esc(addr);
                return ga.description
                  ? `${esc(addr)} ${esc(ga.name)} — ${esc(ga.description)}`
                  : `${esc(addr)} ${esc(ga.name)}`;
              }).join('<br>') || '—'
            : esc((co.group_address_links ?? []).join(', ') || '—');
          html += `<tr><td class="mono">${esc(co.number)}</td><td>${esc(co.name)}</td><td class="mono">${esc(d(co.dpts?.[0]))}</td><td class="mono">${esc(this.flagString(co))}</td><td class="mono">${gaCell}</td></tr>`;
        }
      }
      html += '</tbody></table>';

      // Topology
      html += '<h2>Topologie</h2><table><thead><tr><th>Bereich</th><th>Linie</th><th>Adresse</th><th>Name</th><th>Hersteller</th></tr></thead><tbody>';
      for (const [areaId, area] of Object.entries(this.project?.topology ?? {})) {
        for (const [lineId, line] of Object.entries(area.lines ?? {})) {
          for (const addr of (line.devices ?? [])) {
            const dev = this.project?.devices?.[addr];
            html += `<tr><td>${esc(areaId)} – ${esc(area.name)}</td><td>${esc(areaId)}.${esc(lineId)} – ${esc(line.name)}</td><td class="mono">${esc(addr)}</td><td>${esc(dev?.name??'')}</td><td>${esc(dev?.manufacturer_name??'')}</td></tr>`;
          }
        }
      }
      html += '</tbody></table>';

      // Functions
      const fns = Object.values(this.project?.functions ?? {});
      if (fns.length) {
        html += '<h2>Funktionen</h2><table><thead><tr><th>Name</th><th>Typ</th><th>Gruppenadressen</th></tr></thead><tbody>';
        for (const fn of fns) {
          const gas = Object.values(fn.group_addresses ?? {}).map(r => r.address).join(', ');
          html += `<tr><td>${esc(fn.name)}</td><td>${esc(fn.function_type)}</td><td class="mono">${esc(gas||'—')}</td></tr>`;
        }
        html += '</tbody></table>';
      }

      // KNX Security
      const sec = this.project?._security;
      if (sec?.devices?.length || Object.keys(sec?.ga_keys ?? {}).length || (!this.publicMode && sec?.ets_certificates?.length)) {
        html += '<h2>KNX Data Secure</h2>';

        if (sec.devices?.length) {
          html += '<h3>Gerätesicherheit</h3>';
          for (const dev of sec.devices) {
            html += `<h4><span class="mono">${esc(dev.address)}</span> – ${esc(dev.name || '—')}</h4><dl>`;
            if (dev.ip_address != null)           html += `<dt>IP-Adresse</dt><dd class="mono">${esc(dev.ip_address)}</dd>`;
            if (dev.mac_address != null)          html += `<dt>MAC-Adresse</dt><dd class="mono">${esc(dev.mac_address)}</dd>`;
            if (dev.tool_key != null)             html += `<dt>Tool Key</dt><dd class="mono">${esc(this._b64ToHex(dev.tool_key))}</dd>`;
            if (dev.device_auth_code != null)     html += `<dt>Auth Code</dt><dd class="mono">${esc(dev.device_auth_code)}</dd>`;
            if (dev.device_mgmt_password != null) html += `<dt>Management Passwort</dt><dd class="mono">${esc(dev.device_mgmt_password)}</dd>`;
            if (dev.sequence_number != null)      html += `<dt>Sequenznummer</dt><dd class="mono">${esc(String(dev.sequence_number))}</dd>`;
            for (const [idx, bi] of (dev.bus_interfaces ?? []).entries())
              html += `<dt>Bus-IF ${idx + 1}</dt><dd class="mono">${esc(bi.password)}</dd>`;
            html += '</dl>';
          }
        }

        const gaKeys = Object.entries(sec.ga_keys ?? {});
        if (gaKeys.length) {
          html += '<h3>Gruppen-Schlüssel</h3><table><thead><tr><th>GA</th><th>Schlüssel</th></tr></thead><tbody>';
          for (const [ga, key] of gaKeys)
            html += `<tr><td class="mono">${esc(ga)}</td><td class="mono">${esc(this._b64ToHex(key))}</td></tr>`;
          html += '</tbody></table>';
        }

        if (!this.publicMode && sec.ets_certificates?.length) {
          html += '<h3>ETS Lizenzzertifikat</h3>';
          for (const cert of sec.ets_certificates) {
            html += '<dl>';
            for (const [label, field, hex] of [['Kunde','CUSTOMER',false],['Lizenznummer','NUMBER',false],['Lizenztyp','LICENSE',false],['Datum','DATE',false],['Public Key','PUBLICKEY',true],['Root Cert','ROOTCERT',true],['Signatur','SIGN',true]])
              if (cert[field] != null) html += `<dt>${esc(label)}</dt><dd class="mono">${esc(hex ? this._b64ToHex(cert[field]) : cert[field])}</dd>`;
            html += '</dl>';
          }
        }
      }

      html += '</body></html>';
      const win = window.open('', '_blank');
      win.document.write(html);
      win.document.close();
      win.focus();
      setTimeout(() => win.print(), 500);
    },

    get projectName() {
      return this.project?.info?.name ?? this.selectedFile?.name ?? 'KNX Projekt';
    },

    _exportBusPDF() {
      const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const css = `
        body{font-family:Arial,sans-serif;font-size:9pt;color:#1f2937;margin:15mm}
        h1{font-size:16pt;border-bottom:2px solid #2563eb;padding-bottom:4px;margin-bottom:12px}
        h2{font-size:12pt;color:#1d4ed8;margin-top:20px;border-bottom:1px solid #d1d5db;page-break-after:avoid}
        table{width:100%;border-collapse:collapse;margin:6px 0;font-size:8pt}
        th{background:#f3f4f6;text-align:left;padding:4px 6px;border:1px solid #d1d5db;font-weight:600}
        td{padding:3px 6px;border:1px solid #d1d5db;vertical-align:top}
        tr:nth-child(even) td{background:#f9fafb}
        .mono{font-family:monospace}
        @media print{h2{page-break-before:auto}}`;
      let html = `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8">
        <title>KNX Bus-Dokumentation</title><style>${css}</style></head><body>
        <h1>KNX Bus-Dokumentation</h1>
        <p style="color:#6b7280;font-size:8pt">Erstellt: ${new Date().toLocaleString('de-DE')}</p>`;
      html += '<h2>Geräte</h2><table><thead><tr><th>PA</th><th>Name</th><th>Beschreibung</th><th>Telegramme</th><th>Letztes Telegramm</th><th>GAs</th></tr></thead><tbody>';
      for (const d of this.busDevices)
        html += `<tr><td class="mono">${esc(d.individual_address)}</td><td>${esc(d.name)}</td><td>${esc(d.description)}</td><td style="text-align:center">${d.count}</td><td class="mono">${esc(d.lastTs)}</td><td class="mono">${esc(d.gas.join(', '))}</td></tr>`;
      html += '</tbody></table>';
      html += '<h2>Gruppenadressen</h2><table><thead><tr><th>Adresse</th><th>Name</th><th>Beschreibung</th><th>Letzter Wert</th><th>Zeitstempel</th><th>Quell-PAs</th></tr></thead><tbody>';
      for (const g of this.busGAs)
        html += `<tr><td class="mono">${esc(g.address)}</td><td>${esc(g.name)}</td><td>${esc(g.description)}</td><td class="mono">${esc(g.lastValue)}</td><td class="mono">${esc(g.lastTs)}</td><td class="mono">${esc(g.srcs.join(', '))}</td></tr>`;
      html += '</tbody></table></body></html>';
      const win = window.open('', '_blank');
      win.document.write(html);
      win.document.close();
      win.focus();
      setTimeout(() => win.print(), 500);
    },

    get infoRows() {
      if (!this.project?.info) return [];
      const info = this.project.info;
      return [
        ['Projektname', info.name],
        ['ETS-Version', info.tool_version],
        ['Gruppenadress-Stil', info.group_address_style],
        ['Zuletzt geändert', info.last_modified],
        ['Erstellt mit', info.created_by],
        ['Sprache', info.language_code],
        ['xknxproject Version', info.xknxproject_version],
      ].filter(([, v]) => v !== undefined && v !== null && v !== '');
    },

    get secureGAs() {
      return Object.values(this.project?.group_addresses ?? {}).filter(ga => ga.data_secure);
    },

    valueClass(v) {
      if (v === 'Ein') return 'text-green-600 font-semibold';
      if (v === 'Aus') return 'text-red-500 font-semibold';
      if (v === '<GroupValueRead />') return 'text-amber-600 cursor-help';
      return 'text-gray-800';
    },

    valueTitle(v, fallback) {
      if (v === '<GroupValueRead />') return 'Keine Antwort empfangen – mögliche Ursachen:\n• Kein Gerät hat das R-Flag für diese GA gesetzt\n• Gerät ist offline oder nicht erreichbar\n• Antwort kam auf einer anderen GA';
      return fallback ?? undefined;
    },

    get allDevices() {
      return Object.values(this.project?.devices ?? {});
    },

    get filteredDevices() {
      const q = this.deviceSearch.toLowerCase();
      if (!q) return this.allDevices;
      return this.allDevices.filter(d =>
        (d.name ?? '').toLowerCase().includes(q) ||
        (d.individual_address ?? '').toLowerCase().includes(q) ||
        (d.manufacturer_name ?? '').toLowerCase().includes(q) ||
        (d.order_number ?? '').toLowerCase().includes(q) ||
        (d.application ?? '').toLowerCase().includes(q)
      );
    },

    get allGAs() {
      return Object.values(this.project?.group_addresses ?? {});
    },

    get gaByAddress() {
      const map = {};
      for (const ga of this.allGAs) map[ga.address] = ga;
      return map;
    },

    coGATooltip(co) {
      const links = co.group_address_links ?? [];
      if (!links.length) return '';
      const map = this.gaByAddress;
      return links.map(addr => {
        const ga = map[addr];
        if (!ga) return addr;
        return ga.description ? `${addr}  ${ga.name}\n${ga.description}` : `${addr}  ${ga.name}`;
      }).join('\n\n');
    },

    get filteredGAs() {
      const q = this.gaSearch.toLowerCase();
      if (!q) return this.allGAs;
      return this.allGAs.filter(ga =>
        (ga.name ?? '').toLowerCase().includes(q) ||
        (ga.address ?? '').toLowerCase().includes(q) ||
        (ga.description ?? '').toLowerCase().includes(q)
      );
    },

    get allCOs() {
      return Object.entries(this.project?.communication_objects ?? {}).map(([key, co]) => ({
        ...co,
        _key: key,
        _device: co.device_address,
      }));
    },

    get filteredCOs() {
      const q = this.coSearch.toLowerCase();
      if (!q) return this.allCOs;
      return this.allCOs.filter(co =>
        (co.name ?? '').toLowerCase().includes(q) ||
        (co._device ?? '').toLowerCase().includes(q) ||
        String(co.number ?? '').includes(q) ||
        (co.group_address_links ?? []).some(ga => ga.toLowerCase().includes(q))
      );
    },


    toggleTopology(key) {
      if (this.expandedTopology.has(key)) {
        this.expandedTopology.delete(key);
      } else {
        this.expandedTopology.add(key);
      }
      this.expandedTopology = new Set(this.expandedTopology);
    },

    // --- Kommunikationsgraph ---

    buildCommGraph() {
      if (!this.project) return;
      const devices = this.project.devices ?? {};
      const gas = this.project.group_addresses ?? {};
      const cos = this.project.communication_objects ?? {};
      const topology = this.project.topology ?? {};

      // Area color palette
      const areaColors = ['#3B82F6','#8B5CF6','#EC4899','#F59E0B','#10B981','#EF4444','#06B6D4','#84CC16'];
      const areaColorMap = {};
      let areaIdx = 0;
      for (const areaKey of Object.keys(topology)) {
        areaColorMap[areaKey] = areaColors[areaIdx % areaColors.length];
        areaIdx++;
      }

      // Build device → area mapping
      const deviceAreaColor = {};
      for (const [areaKey, area] of Object.entries(topology)) {
        const lines = area.lines ?? area.line ?? {};
        for (const [lineKey, line] of Object.entries(lines)) {
          const lineDevices = line.devices ?? [];
          for (const devAddr of lineDevices) {
            deviceAreaColor[devAddr] = areaColorMap[areaKey] ?? '#3B82F6';
          }
        }
      }

      const nodes = [];
      const edges = [];
      const deviceNodeIds = new Set();
      const gaNodeIds = new Set();

      // Traverse GAs → COs → devices
      for (const [gaId, ga] of Object.entries(gas)) {
        const gaAddr = ga.address ?? gaId;
        const gaNodeId = 'ga:' + gaAddr;
        const coIds = ga.communication_object_ids ?? [];
        if (coIds.length === 0) continue;

        if (!gaNodeIds.has(gaNodeId)) {
          gaNodeIds.add(gaNodeId);
          const dptStr = ga.dpt ? (ga.dpt.main + (ga.dpt.sub != null ? '.' + String(ga.dpt.sub).padStart(3,'0') : '')) : '';
          nodes.push({
            id: gaNodeId,
            label: gaAddr + (ga.name ? '\n' + ga.name : ''),
            shape: 'box',
            color: { background: '#D1FAE5', border: '#10B981', highlight: { background: '#A7F3D0', border: '#059669' } },
            font: { size: 11, multi: true },
            title: (ga.name ?? gaAddr) + (dptStr ? '\nDPT: ' + dptStr : '') + (ga.description ? '\n' + ga.description : ''),
            _type: 'ga', _addr: gaAddr, _name: ga.name ?? '', _dpt: dptStr, _desc: ga.description ?? ''
          });
        }

        for (const coId of coIds) {
          const co = cos[coId];
          if (!co) continue;
          const devAddr = co.device_address;
          if (!devAddr) continue;

          const devNodeId = 'dev:' + devAddr;
          if (!deviceNodeIds.has(devNodeId)) {
            deviceNodeIds.add(devNodeId);
            const dev = devices[devAddr];
            const devName = dev?.name ?? devAddr;
            const color = deviceAreaColor[devAddr] ?? '#3B82F6';
            nodes.push({
              id: devNodeId,
              label: devAddr + '\n' + devName,
              shape: 'dot',
              size: 16,
              color: { background: color, border: color, highlight: { background: color, border: '#1E3A5F' } },
              font: { size: 11, color: '#374151', multi: true },
              title: devName + '\n' + devAddr + (dev?.manufacturer_name ? '\n' + dev.manufacturer_name : '') + (dev?.order_number ? '\n' + dev.order_number : ''),
              _type: 'device', _addr: devAddr, _name: devName,
              _detail: (dev?.manufacturer_name ?? '') + (dev?.order_number ? ' (' + dev.order_number + ')' : '')
            });
          }

          const flags = co.flags ?? {};
          const edgeId = devAddr + '|' + gaAddr + '|' + coId;
          if (flags.transmit) {
            edges.push({ id: edgeId, from: devNodeId, to: gaNodeId, arrows: 'to', color: { color: '#F97316', highlight: '#EA580C' }, width: 1.5, title: 'Transmit: ' + (co.name ?? coId) });
          } else if (flags.write || flags.update) {
            edges.push({ id: edgeId, from: gaNodeId, to: devNodeId, arrows: 'to', color: { color: '#3B82F6', highlight: '#1D4ED8' }, width: 1.5, title: (flags.write ? 'Write' : 'Update') + ': ' + (co.name ?? coId) });
          } else {
            edges.push({ id: edgeId, from: devNodeId, to: gaNodeId, dashes: true, color: { color: '#D1D5DB', highlight: '#9CA3AF' }, width: 1, title: co.name ?? coId });
          }
        }
      }

      const totalNodes = nodes.length;
      this._commAllNodes = nodes;
      this._commAllEdges = edges;

      this._commNodes = new vis.DataSet(nodes);
      this._commEdges = new vis.DataSet(edges);

      const container = this.$refs.commGraphContainer;
      if (!container) return;

      // Physics settings based on graph size
      let physicsOpts;
      if (totalNodes > 1000) {
        physicsOpts = { enabled: false };
      } else if (totalNodes > 300) {
        physicsOpts = {
          enabled: true,
          stabilization: { iterations: 200, updateInterval: 25 },
          forceAtlas2Based: { gravitationalConstant: -80, centralGravity: 0.01, springLength: 220, springConstant: 0.08, damping: 0.6, avoidOverlap: 0.8 },
          solver: 'forceAtlas2Based',
          minVelocity: 0.75
        };
      } else {
        physicsOpts = {
          enabled: true,
          stabilization: { iterations: 400, updateInterval: 25 },
          forceAtlas2Based: { gravitationalConstant: -120, centralGravity: 0.005, springLength: 280, springConstant: 0.06, damping: 0.5, avoidOverlap: 1.0 },
          solver: 'forceAtlas2Based',
          minVelocity: 0.5
        };
      }

      const options = {
        nodes: { borderWidth: 1.5, shadow: false, margin: 8 },
        edges: { smooth: { type: 'dynamic' }, width: 1 },
        physics: physicsOpts,
        interaction: { hover: true, tooltipDelay: 200, navigationButtons: true, keyboard: true },
        layout: { improvedLayout: totalNodes < 200 }
      };

      if (this.commNetwork) this.commNetwork.destroy();
      this.commNetwork = new vis.Network(container, { nodes: this._commNodes, edges: this._commEdges }, options);

      this.commGraphStats = { devices: deviceNodeIds.size, gas: gaNodeIds.size, edges: edges.length };

      this.commNetwork.once('stabilizationIterationsDone', () => {
        this.commNetwork.setOptions({ physics: { enabled: false } });
        this.commGraphReady = true;
      });
      // If physics disabled from start, mark ready immediately
      if (!physicsOpts.enabled) {
        this.commGraphReady = true;
      }

      // Event handlers
      this.commNetwork.on('click', (params) => {
        if (params.nodes.length === 0) { this.commSelectedNode = null; return; }
        const nodeId = params.nodes[0];
        const node = this._commNodes.get(nodeId);
        if (!node) return;
        const connectedEdges = this.commNetwork.getConnectedEdges(nodeId);
        const connectedNodes = this.commNetwork.getConnectedNodes(nodeId);
        const neighbors = connectedNodes.map(nid => {
          const n = this._commNodes.get(nid);
          return n ? { id: nid, label: n._addr + (n._name ? ' ' + n._name : ''), type: n._type } : null;
        }).filter(Boolean);
        this.commSelectedNode = {
          type: node._type, addr: node._addr, label: node._addr + (node._name ? ' — ' + node._name : ''),
          detail: node._type === 'device' ? node._detail : ('DPT: ' + (node._dpt || '—') + (node._desc ? ' | ' + node._desc : '')),
          neighbors
        };
        // Clicking a GA or device node filters the graph to that node and its neighbors
        this.commGraphFilter = node._addr;
        this.filterCommGraph();
      });

      this.commNetwork.on('doubleClick', (params) => {
        if (params.nodes.length === 0) return;
        const nodeId = params.nodes[0];
        const connected = this.commNetwork.getConnectedNodes(nodeId);
        this.commNetwork.fit({ nodes: [nodeId, ...connected], animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
      });
    },

    filterCommGraph() {
      if (!this.commNetwork || !this._commAllNodes) return;
      const q = this.commGraphFilter.trim().toLowerCase();
      if (!q) { this.resetCommGraphView(); return; }

      const matchIds = new Set();
      for (const node of this._commAllNodes) {
        const text = (node._addr + ' ' + node._name + ' ' + (node._detail ?? '') + ' ' + (node._dpt ?? '') + ' ' + (node._desc ?? '')).toLowerCase();
        if (text.includes(q)) matchIds.add(node.id);
      }
      // Add 1-hop neighbors
      const neighborIds = new Set(matchIds);
      for (const edge of this._commAllEdges) {
        if (matchIds.has(edge.from)) neighborIds.add(edge.to);
        if (matchIds.has(edge.to)) neighborIds.add(edge.from);
      }

      const filteredNodes = this._commAllNodes.filter(n => neighborIds.has(n.id));
      const filteredEdges = this._commAllEdges.filter(e => neighborIds.has(e.from) && neighborIds.has(e.to));

      this._commNodes.clear();
      this._commNodes.add(filteredNodes);
      this._commEdges.clear();
      this._commEdges.add(filteredEdges);

      const deviceCount = filteredNodes.filter(n => n._type === 'device').length;
      const gaCount = filteredNodes.filter(n => n._type === 'ga').length;
      this.commGraphStats = { devices: deviceCount, gas: gaCount, edges: filteredEdges.length };

      // Re-run physics so filtered nodes redistribute cleanly
      this.commNetwork.setOptions({ physics: { enabled: true } });
      this.commNetwork.once('stabilizationIterationsDone', () => {
        this.commNetwork.setOptions({ physics: { enabled: false } });
        this.commNetwork.fit({ animation: { duration: 300 } });
      });
      this.commNetwork.stabilize(200);
    },

    resetCommGraphView() {
      if (!this.project) return;
      this.commSelectedNode = null;
      this.commGraphFilter = '';
      this.commGraphReady = false;
      this.$nextTick(() => this.buildCommGraph());
    },

    navigateToDeviceCOs(addr) {
      this.coSearch = '';
      this.highlightedCO = null;
      this.expandedCODevices = new Set([...this.expandedCODevices, addr]);
      this.activeTab = 'com_objects';
    },

    navigateToCO(coId) {
      const co = this.project?.communication_objects?.[coId];
      if (!co) return;
      this.coSearch = '';
      this.highlightedCO = coId;
      this.expandedCODevices = new Set([...this.expandedCODevices, co.device_address]);
      this.activeTab = 'com_objects';
    },

    navigateToGA(co) {
      const links = co.group_address_links ?? [];
      if (links.length === 0) return;
      this.gaSearch = links[0];
      this.activeTab = 'group_addresses';
    },

    toggleCODevice(addr) {
      if (this.expandedCODevices.has(addr)) {
        this.expandedCODevices.delete(addr);
      } else {
        this.expandedCODevices.add(addr);
      }
      this.expandedCODevices = new Set(this.expandedCODevices);
    },

    dptTitle(dpt) {
      if (!dpt) return '';
      const names = {
        '1':'1-Bit Boolean','1.001':'Schalten (Aus/Ein)','1.002':'Boolean','1.003':'Freigabe',
        '1.004':'Rampe','1.005':'Alarm','1.006':'Binärwert','1.007':'Schritt',
        '1.008':'Auf/Ab','1.009':'Öffnen/Schließen','1.010':'Fehler','1.011':'Zustand',
        '2':'2-Bit Zwangssteuerung','2.001':'Schalten (zwangsgesteuert)','2.002':'Boolean (zwangsgesteuert)',
        '3':'4-Bit Dimmen/Jalousie','3.007':'Lichtstärke dimmen','3.008':'Jalousie fahren',
        '4':'8-Bit Zeichen','4.001':'ASCII','4.002':'ISO 8859-1',
        '5':'8-Bit Unsigned','5.001':'Prozentwert (0–100 %)','5.003':'Winkel (0–360°)',
        '5.004':'Prozentwert (0–255)','5.005':'Dezimalwert (0–255)','5.010':'Pulszähler',
        '6':'8-Bit Signed','6.001':'Prozentwert (−128–127 %)','6.010':'Pulszähler',
        '7':'2-Byte Unsigned','7.001':'Pulszähler','7.002':'Zeitraum (ms)',
        '7.003':'Zeitraum (10 ms)','7.004':'Zeitraum (100 ms)','7.005':'Zeitraum (s)',
        '7.006':'Zeitraum (min)','7.007':'Zeitraum (h)','7.011':'Länge (mm)','7.012':'Strom (mA)',
        '8':'2-Byte Signed','8.001':'Pulsdifferenz','8.002':'Zeitraum (10 ms)',
        '9':'2-Byte Float','9.001':'Temperatur (°C)','9.002':'Temperaturdifferenz (K)',
        '9.003':'Kelvin/Stunde','9.004':'Beleuchtungsstärke (Lux)','9.005':'Windgeschwindigkeit (m/s)',
        '9.006':'Druck (Pa)','9.007':'Luftfeuchtigkeit (%)','9.008':'Luftqualität (ppm)',
        '9.009':'Zeitraum (s)','9.010':'Zeitraum (ms)','9.011':'Spannung (mV)',
        '9.020':'Spannung (mV)','9.021':'Strom (mA)','9.022':'Leistungsdichte (W/m²)',
        '9.024':'Leistung (kW)','9.025':'Volumenfluss (l/h)','9.026':'Liter',
        '10':'Uhrzeit (3 Byte)','10.001':'Uhrzeit mit Wochentag',
        '11':'Datum (3 Byte)','11.001':'Datum',
        '12':'4-Byte Unsigned','12.001':'Pulszähler',
        '13':'4-Byte Signed','13.001':'Pulszähler','13.010':'Pulsdifferenz',
        '13.013':'Durchfluss (l/h)',
        '14':'4-Byte Float','14.007':'Winkel (°)','14.019':'Spannung (V)',
        '14.027':'Stromstärke (A)','14.031':'Frequenz (Hz)','14.033':'Wärme (J)',
        '14.056':'Wirkleistung (W)','14.057':'Scheinleistung (VA)',
        '14.068':'Temperatur (°C)','14.076':'Volumen (m³)',
        '16':'Zeichenkette (14 Byte ASCII)','16.001':'Zeichenkette (ISO 8859-1)',
        '17':'Szenen-Nummer (1–64)','18':'Szenen-Aktivierung/Speicherung',
        '19':'Datum und Uhrzeit (8 Byte)',
        '20':'1-Byte Aufzählung','20.001':'Systemuhr-Modus','20.002':'Bausystem-Modus',
        '20.102':'HVAC Betriebsart','20.103':'HVAC Steuerung','20.105':'HVAC Zusatz-Betriebsart',
        '21':'8-Bit Statusfeld','22':'16-Bit Statusfeld',
        '29':'8-Byte Signed','29.001':'Impulszähler','29.002':'Pulsdifferenz','29.010':'Wirkenergie (Wh)',
        '232':'RGB-Farbe (3 Byte)','232.600':'RGB (Rot/Grün/Blau)',
        '251':'RGBW-Farbe (6 Byte)',
      };
      const subKey = dpt.sub != null ? `${dpt.main}.${String(dpt.sub).padStart(3,'0')}` : null;
      return names[subKey] || names[String(dpt.main)] || (subKey ? `DPT ${subKey}` : `DPT ${dpt.main}`);
    },

    flagTitle(ko) {
      const f = ko.flags ?? {};
      const lines = [];
      if (f.communication) lines.push('C – Kommunikation (Objekt nimmt am Bus teil)');
      if (f.read)          lines.push('R – Lesen (Wert kann abgefragt werden)');
      if (f.write)         lines.push('W – Schreiben (Wert kann gesetzt werden)');
      if (f.transmit)      lines.push('T – Senden (Wert wird bei Änderung gesendet)');
      if (f.update)        lines.push('U – Aktualisieren (Wert wird bei Empfang übernommen)');
      if (f.read_on_init)  lines.push('I – Lesen bei Initialisierung');
      return lines.join('\n') || 'Keine Flags gesetzt';
    },

    flagString(ko) {
      const f = ko.flags ?? {};
      const flags = [];
      if (f.read) flags.push('R');
      if (f.write) flags.push('W');
      if (f.transmit) flags.push('T');
      if (f.update) flags.push('U');
      if (f.communication) flags.push('C');
      return flags.join('') || '—';
    },

    deviceCOs(addr) {
      return this.allCOs.filter(co => co._device === addr);
    },

    get cosByDevice() {
      const grouped = {};
      for (const co of this.filteredCOs) {
        if (!grouped[co._device]) grouped[co._device] = [];
        grouped[co._device].push(co);
      }
      return Object.entries(grouped).map(([addr, cos]) => ({
        addr,
        deviceName: this.project?.devices?.[addr]?.name ?? addr,
        cos: cos.sort((a, b) => (a.number ?? 0) - (b.number ?? 0)),
      }));
    },

    // ── XLSX export ───────────────────────────────────────
    async exportXLSX() {
      try {
        const res = this.publicMode
          ? await fetch('/api/export/xlsx', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(this.project),
            })
          : await fetch('/api/export/xlsx');
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          alert('Fehler: ' + (err.detail || `HTTP ${res.status}`));
          return;
        }
        const blob = await res.blob();
        const cd = res.headers.get('content-disposition') || '';
        const m = cd.match(/filename="?([^"]+)"?/);
        const fname = m ? m[1] : 'export.xlsx';
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = fname;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
      } catch (e) {
        alert('Netzwerkfehler: ' + e.message);
      }
    },

    // ── Snapshots ─────────────────────────────────────────
    async loadSnapshots() {
      try {
        const res = await fetch('/api/snapshots');
        if (res.ok) {
          const data = await res.json();
          this.snapshots = data.snapshots || [];
        }
      } catch (_) {}
    },

    async createSnapshot() {
      this.snapshotSaving = true;
      try {
        const res = await fetch('/api/snapshots', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: this.snapshotName }),
        });
        if (res.ok) {
          this.snapshotName = '';
          await this.loadSnapshots();
        } else {
          const err = await res.json().catch(() => ({}));
          alert('Fehler: ' + (err.detail || 'Snapshot konnte nicht angelegt werden'));
        }
      } catch (e) {
        alert('Netzwerkfehler: ' + e.message);
      } finally {
        this.snapshotSaving = false;
      }
    },

    async deleteSnapshot(id) {
      if (!confirm('Snapshot wirklich löschen?')) return;
      try {
        const res = await fetch(`/api/snapshots/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (res.ok) {
          await this.loadSnapshots();
          if (this.diffA === id) this.diffA = '';
          if (this.diffB === id) this.diffB = 'current';
          this.diffRows = [];
          this.diffStats = null;
        }
      } catch (e) {
        alert('Netzwerkfehler: ' + e.message);
      }
    },

    async runDiff() {
      if (!this.diffA || !this.diffB) return;
      this.diffLoading = true;
      try {
        const url = `/api/snapshots/diff?a=${encodeURIComponent(this.diffA)}&b=${encodeURIComponent(this.diffB)}`;
        const res = await fetch(url);
        if (res.ok) {
          const data = await res.json();
          this.diffRows = data.rows || [];
          this.diffStats = data.stats || null;
        } else {
          const err = await res.json().catch(() => ({}));
          alert('Fehler: ' + (err.detail || 'Diff konnte nicht berechnet werden'));
        }
      } catch (e) {
        alert('Netzwerkfehler: ' + e.message);
      } finally {
        this.diffLoading = false;
      }
    },

    get filteredDiffRows() {
      if (!this.diffOnlyChanges) return this.diffRows;
      return this.diffRows.filter(r => r.status !== 'equal');
    },

    // ── GA activity sparkline ─────────────────────────────
    _parseValueForSpark(value) {
      if (value == null) return { num: null, bool: null };
      const s = String(value).trim();
      const lower = s.toLowerCase();
      if (lower === 'ein' || lower === 'on'  || lower === 'true'  || lower === '1') return { num: 1, bool: 1 };
      if (lower === 'aus' || lower === 'off' || lower === 'false' || lower === '0') return { num: 0, bool: 0 };
      const m = s.match(/-?\d+(?:[.,]\d+)?/);
      if (!m) return { num: null, bool: null };
      return { num: parseFloat(m[0].replace(',', '.')), bool: null };
    },

    _pushGAHistory(ga, value, ts) {
      const parsed = this._parseValueForSpark(value);
      if (parsed.num == null) return;
      const buf = this.gaHistory[ga] ? [...this.gaHistory[ga]] : [];
      buf.push({ ts, value, ...parsed });
      if (buf.length > this.gaHistoryMax) buf.shift();
      this.gaHistory = { ...this.gaHistory, [ga]: buf };
    },

    _rebuildGAHistory(entries) {
      const map = {};
      // entries arrive newest-first; iterate reverse to keep chronological order
      for (let i = entries.length - 1; i >= 0; i--) {
        const e = entries[i];
        if (!e || !e.ga) continue;
        const parsed = this._parseValueForSpark(e.value);
        if (parsed.num == null) continue;
        if (!map[e.ga]) map[e.ga] = [];
        map[e.ga].push({ ts: e.ts, value: e.value, ...parsed });
        if (map[e.ga].length > this.gaHistoryMax) map[e.ga].shift();
      }
      this.gaHistory = map;
    },

    renderSparkline(ga) {
      const buf = this.gaHistory[ga];
      if (!buf || buf.length === 0) return '<span class="text-gray-300 text-xs">—</span>';
      const W = 64, H = 18, PAD = 2;
      const allBool = buf.every(b => b.bool != null);
      if (buf.length === 1) {
        const x = W / 2, y = H / 2;
        return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><circle cx="${x}" cy="${y}" r="2.5" fill="#3b82f6"/></svg>`;
      }
      const xs = (i) => PAD + (i * (W - 2 * PAD)) / (buf.length - 1);
      if (allBool) {
        // Step line between 0 (bottom) and 1 (top)
        let d = '';
        for (let i = 0; i < buf.length; i++) {
          const x = xs(i);
          const y = buf[i].bool === 1 ? PAD + 1 : H - PAD - 1;
          d += (i === 0 ? `M${x},${y}` : ` L${x},${y}`);
          if (i < buf.length - 1) {
            const nextY = buf[i + 1].bool === 1 ? PAD + 1 : H - PAD - 1;
            const nextX = xs(i + 1);
            if (nextY !== y) d += ` L${nextX},${y}`;
          }
        }
        return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><path d="${d}" stroke="#3b82f6" stroke-width="1.5" fill="none" stroke-linejoin="miter"/></svg>`;
      }
      // Numeric line graph
      const vals = buf.map(b => b.num);
      let min = Math.min(...vals), max = Math.max(...vals);
      if (min === max) { min -= 1; max += 1; }
      const ys = (v) => H - PAD - ((v - min) / (max - min)) * (H - 2 * PAD);
      let d = '';
      for (let i = 0; i < buf.length; i++) {
        d += (i === 0 ? 'M' : ' L') + xs(i).toFixed(1) + ',' + ys(buf[i].num).toFixed(1);
      }
      return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><path d="${d}" stroke="#3b82f6" stroke-width="1.2" fill="none" stroke-linejoin="round"/></svg>`;
    },

    sparkTooltip(ga) {
      const buf = this.gaHistory[ga];
      if (!buf || !buf.length) return 'Noch keine Telegramme';
      const N = 15;
      const recent = buf.slice(-N).reverse(); // newest first
      const lines = recent.map(e => {
        const time = (e.ts || '').split(' ').pop() || e.ts;
        return `${time}   ${e.value}`;
      });
      const head = `${buf.length} Telegramme (letzte ${recent.length}):`;
      return [head, ...lines].join('\n');
    },

    // ── Global search ─────────────────────────────────────
    openSearch() {
      this.searchOpen = true;
      this.searchQuery = '';
      this.searchIndex = 0;
      this.$nextTick(() => document.getElementById('global-search-input')?.focus());
    },

    get searchResults() {
      const q = this.searchQuery.trim().toLowerCase();
      if (!q || !this.project) return [];
      const out = [];
      const LIMIT = 50;

      for (const ga of this.allGAs ?? []) {
        if (out.length >= LIMIT) break;
        const dpt = ga.dpt ? (ga.dpt.main + (ga.dpt.sub != null ? '.' + String(ga.dpt.sub).padStart(3,'0') : '')) : '';
        if ((ga.address ?? '').toLowerCase().includes(q) ||
            (ga.name ?? '').toLowerCase().includes(q) ||
            (ga.description ?? '').toLowerCase().includes(q)) {
          out.push({ type: 'ga', label: ga.name || '(unbenannt)',
                     sub: ga.address + (dpt ? ' · DPT ' + dpt : '') + (ga.description ? ' · ' + ga.description : ''),
                     payload: ga.address });
        }
      }
      for (const dev of Object.values(this.project.devices ?? {})) {
        if (out.length >= LIMIT) break;
        if ((dev.individual_address ?? '').toLowerCase().includes(q) ||
            (dev.name ?? '').toLowerCase().includes(q) ||
            (dev.manufacturer_name ?? '').toLowerCase().includes(q) ||
            (dev.order_number ?? '').toLowerCase().includes(q)) {
          out.push({ type: 'device', label: dev.name || '(unbenannt)',
                     sub: dev.individual_address + ' · ' + (dev.manufacturer_name ?? ''),
                     payload: dev.individual_address });
        }
      }
      for (const fn of Object.values(this.project.functions ?? {})) {
        if (out.length >= LIMIT) break;
        if ((fn.name ?? '').toLowerCase().includes(q)) {
          out.push({ type: 'function', label: fn.name, sub: fn.identifier ?? '', payload: fn.identifier });
        }
      }
      const walk = (spaces) => {
        for (const sp of Object.values(spaces ?? {})) {
          if (out.length >= LIMIT) return;
          if ((sp.name ?? '').toLowerCase().includes(q)) {
            out.push({ type: 'location', label: sp.name, sub: sp.type ?? 'Standort', payload: sp.identifier });
          }
          walk(sp.spaces);
        }
      };
      walk(this.project.locations);
      return out;
    },

    selectSearchResult(r) {
      this.searchOpen = false;
      if (r.type === 'ga')         { this.gaSearch = r.payload;     this.activeTab = 'group_addresses'; }
      else if (r.type === 'device'){ this.deviceSearch = r.payload; this.activeTab = 'devices'; }
      else if (r.type === 'function')  { this.activeTab = 'functions'; }
      else if (r.type === 'location')  { this.activeTab = 'locations'; }
    },

    // ── CSV export ────────────────────────────────────────
    _csvEscape(v) {
      if (v == null) return '';
      const s = String(v);
      return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    },

    _downloadCSV(stem, rows) {
      if (!rows.length) return;
      const headers = Object.keys(rows[0]);
      const lines = [headers.join(',')];
      for (const r of rows) lines.push(headers.map(h => this._csvEscape(r[h])).join(','));
      const blob = new Blob(['﻿' + lines.join('\n')], { type: 'text/csv;charset=utf-8' });
      const projectStem = (this.project?.info?.name ?? 'export').replace(/[^a-z0-9_-]+/gi, '_');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${stem}-${projectStem}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
    },

    exportDevicesCSV() {
      const rows = (this.filteredDevices ?? []).map(d => ({
        Adresse: d.individual_address,
        Name: d.name ?? '',
        Hersteller: d.manufacturer_name ?? '',
        Bestellnr: d.order_number ?? '',
        Applikation: d.application ?? '',
        KOs: d.communication_object_ids?.length ?? 0,
      }));
      this._downloadCSV('geraete', rows);
    },

    exportGAsCSV() {
      const rows = (this.filteredGAs ?? []).map(g => ({
        Adresse: g.address,
        Name: g.name ?? '',
        DPT: g.dpt ? (g.dpt.main + (g.dpt.sub != null ? '.' + String(g.dpt.sub).padStart(3,'0') : '')) : '',
        Beschreibung: g.description ?? '',
        Verknuepfte_KOs: (g.communication_object_ids ?? []).join('; '),
      }));
      this._downloadCSV('group-addresses', rows);
    },

    exportCOsCSV() {
      const rows = [];
      for (const grp of this.cosByDevice ?? []) {
        for (const co of grp.cos) {
          rows.push({
            Geraet_PA: grp.addr,
            Geraet: grp.deviceName,
            KO_Nr: co.number,
            Name: co.name ?? '',
            DPT: co.dpts?.[0] ? (co.dpts[0].main + (co.dpts[0].sub != null ? '.' + String(co.dpts[0].sub).padStart(3,'0') : '')) : '',
            Flags: this.flagString(co),
            Gruppenadressen: (co.group_address_links ?? []).join('; '),
          });
        }
      }
      this._downloadCSV('kommunikationsobjekte', rows);
    },

    renderSpace(space, depth) {
      if (!space) return '';
      const indent = depth * 16;
      const items = Object.values(space.spaces ?? {});
      const fns = space.functions ?? [];
      let html = '';

      for (const child of items) {
        const typeLabel = child.type ? `<span class="text-xs bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded mr-2">${child.type}</span>` : '';
        html += `<div class="border-b last:border-b-0">`;
        html += `<div class="flex items-center gap-2 py-2 hover:bg-gray-50" style="padding-left: ${8 + indent}px">`;
        html += `${typeLabel}<span class="text-sm text-gray-700">${child.name ?? ''}</span>`;
        html += `</div>`;
        if (child.spaces && Object.keys(child.spaces).length > 0) {
          html += this.renderSpace(child, depth + 1);
        }
        if (child.devices && child.devices.length > 0) {
          for (const addr of child.devices) {
            const devName = this.project?.devices?.[addr]?.name ?? '';
            html += `<div class="py-1 text-xs text-gray-700 hover:bg-blue-50 cursor-pointer" style="padding-left: ${8 + indent + 16}px" onclick="window.__knxNavDevice('${addr}')">📟 <span class="font-mono text-gray-500">${addr}</span> <span>${devName}</span></div>`;
          }
        }
        if (child.functions && child.functions.length > 0) {
          for (const fn of child.functions) {
            const fnData = this.project?.functions?.[fn];
            if (fnData) {
              html += `<div class="py-1 text-xs text-blue-600" style="padding-left: ${8 + indent + 16}px">⚡ ${fnData.name}</div>`;
            }
          }
        }
        html += `</div>`;
      }

      for (const fnId of fns) {
        const fnData = this.project?.functions?.[fnId];
        if (fnData) {
          html += `<div class="py-1 text-xs text-blue-600 border-b last:border-b-0" style="padding-left: ${8 + indent}px">⚡ ${fnData.name}</div>`;
        }
      }
      return html;
    },
  };
}
