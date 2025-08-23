// MikroTik Monitoring Dashboard JavaScript

document.addEventListener('DOMContentLoaded', () => {
    // Debug helper functions
    let debugSettings = {};
    let debugPanelEnabled = false;
    let debugLogs = [];
    let maxDebugLogs = 500; // Limit to prevent memory issues
    
    const loadDebugSettings = async () => {
        try {
            const response = await fetch('/api/settings');
            const settings = await response.json();
            debugSettings = settings;
            
            // Check if debug panel should be enabled
            debugPanelEnabled = settings.debug_terminal === 'true';
            updateDebugPanelVisibility();
            
            // If debug is enabled and we have existing logs, update display
            if (debugPanelEnabled && debugLogs.length > 0) {
                updateDebugPanelContent();
            }
        } catch (error) {
            console.error('Failed to load debug settings:', error);
            // On error, hide debug panel
            debugPanelEnabled = false;
            updateDebugPanelVisibility();
        }
    };
    
    const debugLog = (debugType, message, ...args) => {
        // Early exit if debug system is completely disabled - no processing at all
        if (!debugSettings || typeof debugSettings !== 'object') {
            return; // No debug settings loaded, skip entirely
        }
        
        const isEnabled = debugSettings.debug_terminal === 'true';
        
        if (isEnabled) {
            // Always log to console
            
            // If debug panel is enabled, also add to panel
            if (debugPanelEnabled && debugSettings.debug_terminal === 'true') {
                addLogToPanel(debugType, message, args);
            }
        }
    };
    
    const addLogToPanel = (debugType, message, args) => {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = {
            timestamp,
            type: debugType,
            message,
            args: args.length > 0 ? args : null,
            id: Date.now() + Math.random()
        };
        
        debugLogs.push(logEntry);
        
        // Keep only recent logs to prevent memory issues
        if (debugLogs.length > maxDebugLogs) {
            debugLogs = debugLogs.slice(-maxDebugLogs);
        }
        
        updateDebugPanelContent();
    };
    
    const updateDebugPanelContent = () => {
        const debugPanelContent = document.getElementById('debugPanelContent');
        if (!debugPanelContent) return;
        
        // Show last 100 logs in reverse order (newest first)
        const recentLogs = debugLogs.slice(-100).reverse();
        
        debugPanelContent.innerHTML = recentLogs.map(log => {
            const argsText = log.args ? formatArgs(log.args) : '';
            return `
                <div class="debug-log-entry ${log.type}">
                    <span class="debug-timestamp">${log.timestamp}</span>
                    <span class="debug-type">[${log.type.toUpperCase()}]</span>
                    <span class="debug-message">${escapeHtml(log.message)}</span>
                    ${argsText ? `<div class="debug-args">${argsText}</div>` : ''}
                </div>
            `;
        }).join('');
        
        // Auto-scroll to bottom (newest entries)
        debugPanelContent.scrollTop = 0;
    };
    
    const formatArgs = (args) => {
        return args.map(arg => {
            if (typeof arg === 'object') {
                try {
                    return escapeHtml(JSON.stringify(arg, null, 2));
                } catch (e) {
                    return escapeHtml(String(arg));
                }
            }
            return escapeHtml(String(arg));
        }).join(' ');
    };
    
    const escapeHtml = (text) => {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };
    
    const updateDebugPanelVisibility = () => {
        const debugPanel = document.getElementById('debugPanel');
        
        if (!debugPanel) return;
        
        // Debug panel sa zobrazuje priamo na základe nastavení
        debugPanelEnabled = debugSettings.debug_terminal === 'true';
        
        if (debugPanelEnabled) {
            debugPanel.classList.add('visible');
        } else {
            debugPanel.classList.remove('visible');
        }
    };
    
    const clearDebugLogs = () => {
        debugLogs = [];
        updateDebugPanelContent();
    };
    
    const copyDebugLogs = () => {
        const logText = debugLogs.map(log => {
            const argsText = log.args ? ` ${formatArgs(log.args)}` : '';
            return `${log.timestamp} [${log.type.toUpperCase()}] ${log.message}${argsText}`;
        }).join('\n');
        
        navigator.clipboard.writeText(logText).then(() => {
            // Show feedback
            const copyBtn = document.getElementById('debugCopyBtn');
            const originalIcon = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = originalIcon;
            }, 1000);
        }).catch(err => {
            console.error('Failed to copy debug logs:', err);
        });
    };
    
    // Initialize debug panel event listeners
    const initDebugPanel = () => {
        const debugClearBtn = document.getElementById('debugClearBtn');
        const debugCopyBtn = document.getElementById('debugCopyBtn');
        const debugMinimizeBtn = document.getElementById('debugMinimizeBtn');
        const debugCloseBtn = document.getElementById('debugCloseBtn');
        
        if (debugClearBtn) {
            debugClearBtn.addEventListener('click', clearDebugLogs);
        }
        
        if (debugCopyBtn) {
            debugCopyBtn.addEventListener('click', copyDebugLogs);
        }
        
        if (debugMinimizeBtn) {
            debugMinimizeBtn.addEventListener('click', () => {
                const debugPanel = document.getElementById('debugPanel');
                const debugPanelContent = document.getElementById('debugPanelContent');
                if (debugPanelContent.style.display === 'none') {
                    debugPanelContent.style.display = 'flex';
                    debugMinimizeBtn.innerHTML = '<i class="fas fa-minus"></i>';
                } else {
                    debugPanelContent.style.display = 'none';
                    debugMinimizeBtn.innerHTML = '<i class="fas fa-plus"></i>';
                }
            });
        }
        
        if (debugCloseBtn) {
            debugCloseBtn.addEventListener('click', () => {
                const debugPanel = document.getElementById('debugPanel');
                debugPanel.classList.remove('visible');
                // Don't disable completely, just hide - can be re-enabled from settings
            });
        }
    };
    
    // Load debug settings ONLY when needed - not automatically
    // Debug system will be initialized only if debug_terminal is enabled
    
    // Export functions to window for access from settings page
    window.refreshDebugSettings = () => {
        loadDebugSettings();
    };
    
    // Export debugLog function for global access (e.g., from monitoring.html)
    window.debugLog = debugLog;
    
    // Initialize debug system conditionally - ONLY when enabled
    const initializeDebugSystem = async () => {
        try {
            await loadDebugSettings();
            if (debugSettings.debug_terminal === 'true') {
                setTimeout(initDebugPanel, 100);
            }
        } catch (error) {
            console.warn('Debug system initialization skipped due to error:', error);
            debugPanelEnabled = false;
        }
    };
    
    // DON'T start debug system automatically - only when explicitly enabled
    // initializeDebugSystem(); // REMOVED - will be called from focus event if needed
    
    // Listen for settings changes (e.g., from settings page)
    window.addEventListener('storage', function(e) {
        if (e.key === 'settingsChanged' && e.newValue === 'true') {
            setTimeout(() => {
                loadDebugSettings();
                localStorage.removeItem('settingsChanged');
            }, 500);
        }
    });
    
    // Check for settings changes when user returns to the page
    window.addEventListener('focus', function() {
        // Only check if we haven't checked recently (debounce)
        if (!window._lastFocusCheck || Date.now() - window._lastFocusCheck > 5000) {
            // First check if debug is needed, then initialize only if enabled
            loadDebugSettings().then(() => {
                if (debugSettings.debug_terminal === 'true' && !debugPanelEnabled) {
                    // Initialize debug system only if it wasn't initialized before
                    initializeDebugSystem();
                }
            }).catch(error => {
                console.warn('Focus debug check failed:', error);
            });
            window._lastFocusCheck = Date.now();
        }
    });
    
    // Keyboard shortcut for debug panel (Ctrl+D or Cmd+D)
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'd' && debugSettings.debug_terminal === 'true') {
            e.preventDefault();
            const debugPanel = document.getElementById('debugPanel');
            
            if (debugPanel) {
                if (debugPanel.classList.contains('visible')) {
                    debugPanel.classList.remove('visible');
                } else {
                    debugPanel.classList.add('visible');
                    updateDebugPanelContent();
                }
            }
        }
    });
    
    // Chart.js availability will be logged only if debug is enabled

    const API_URL = '';
    // Custom device selector elements
    const deviceSelectorContainer = document.getElementById('deviceSelectorContainer');
    const deviceSelectorButton = document.getElementById('deviceSelectorButton');
    const deviceSelectorText = document.getElementById('deviceSelectorText');
    const deviceSelectorDropdown = document.getElementById('deviceSelectorDropdown');
    // Legacy reference for compatibility
    const deviceSelector = {
        value: '',
        innerHTML: '',
        querySelector: (selector) => deviceSelectorDropdown.querySelector(selector),
        querySelectorAll: (selector) => deviceSelectorDropdown.querySelectorAll(selector),
        addEventListener: (event, handler) => {
            if (event === 'change') {
                window._deviceChangeHandler = handler;
            }
        }
    };
    const deviceInfoPanel = document.getElementById('deviceInfoPanel');
    const chartsContainer = document.getElementById('chartsContainer');
    const noDeviceSelected = document.getElementById('noDeviceSelected');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const refreshBtn = document.getElementById('refreshBtn');
    const deviceSettingsBtn = document.getElementById('deviceSettingsBtn');
    const pauseResumeBtn = document.getElementById('pauseResumeBtn');
    const pauseResumeIcon = document.getElementById('pauseResumeIcon');
    const pauseResumeText = document.getElementById('pauseResumeText');
    const deviceSettingsModal = document.getElementById('deviceSettingsModal');
    const deviceSettingsForm = document.getElementById('deviceSettingsForm');
    const closeSettingsModal = document.getElementById('closeSettingsModal');
    const cancelSettings = document.getElementById('cancelSettings');
    const settingsDeviceInfo = document.getElementById('settingsDeviceInfo');
    const pingIntervalInput = document.getElementById('pingInterval');
    const snmpIntervalInput = document.getElementById('snmpInterval');
    const timeRangeContainer = document.getElementById('timeRangeContainer');
    
    let currentDeviceId = null;
    let currentTimeRange = '24h'; // Predvolený časový rozsah
    let charts = {};
    let pingUpdateInterval = null;
    let socket = null;
    let isLoadingData = false; // Flag to prevent multiple simultaneous requests
    let lastTotalMemoryValue = null; // For real-time forward-fill
    
    // Export charts to window for access from monitoring.html
    window.charts = charts;
    
    // Device status cache for efficient status tracking
    let deviceStatusCache = new Map();
    
    // DOM elements cache for better performance
    const domCache = {};
    
    // Cache frequently used DOM elements
    const cacheDOM = () => {
        domCache.chartContainers = document.querySelectorAll('.chart-container');
        domCache.timeRangeButtons = document.querySelectorAll('.time-range-btn');
        domCache.deviceName = document.getElementById('deviceName');
        domCache.deviceIp = document.getElementById('deviceIp');
        domCache.deviceModel = document.getElementById('deviceModel');
        domCache.pingStatus = document.getElementById('pingStatus');
        domCache.avgLatency = document.getElementById('avgLatency');
        domCache.packetLoss = document.getElementById('packetLoss');
        domCache.lastPing = document.getElementById('lastPing');
    };
    
    // Device status management functions
    const getStatusIndicator = (status, isPaused = false) => {
        if (isPaused) {
            return '⏸️'; // Pause symbol for paused devices
        }
        switch (status) {
            case 'online':
                return '🟢'; // Green dot
            case 'offline':
                return '🔴'; // Red dot
            default:
                return '⚪'; // White dot for unknown
        }
    };    const updateDeviceStatus = (deviceId, status) => {
        deviceStatusCache.set(deviceId, status);
        updateDeviceStatusInSelector(deviceId, status);
    };
    
    const updateDeviceStatusInSelector = (deviceId, status, isPaused = null) => {
        // Use custom dropdown API if available
        if (window.customDeviceSelector) {
            window.customDeviceSelector.updateDeviceStatus(deviceId, status, isPaused);
            return;
        }
        
        // Legacy fallback
        const options = deviceSelector.querySelectorAll('option[value]');
        options.forEach(option => {
            if (option.value == deviceId) {
                // Always use stored data attributes for reliable device text
                const deviceName = option.getAttribute('data-name');
                const deviceIp = option.getAttribute('data-ip');
                
                // Use provided paused status or get from data attribute
                const pausedStatus = isPaused !== null ? isPaused : (option.getAttribute('data-paused') === 'true');
                
                let deviceText;
                if (deviceName && deviceIp) {
                    // Use stored data attributes (most reliable)
                    deviceText = `${deviceName} (${deviceIp})`;
                } else {
                    // Fallback: try to extract from current text with more robust regex
                    const currentText = option.textContent;
                    
                    // Remove any emoji/status indicators at the beginning using comprehensive patterns
                    let cleanText = currentText
                        // Remove common status emojis and pause symbol
                        .replace(/^[🟢🔴⚪⚫🟡🔵🟤🟠🟣⏸️]\s*/g, '')
                        // Remove any remaining unicode emoji at start
                        .replace(/^[\u{1F300}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]\s*/gu, '')
                        // Remove question marks that might appear due to encoding issues
                        .replace(/^\?+\s*/g, '')
                        // Remove any remaining non-alphanumeric chars at start (except parentheses and spaces)
                        .replace(/^[^\w\s\(\)\.]+\s*/g, '');
                    
                    deviceText = cleanText.trim();
                    
                    // If still no valid format, try to extract name(ip) pattern
                    if (!deviceText.includes('(') || !deviceText.includes(')')) {
                        // Last resort: assume the format and extract what we can
                        const match = currentText.match(/(.+\(.+\))/);
                        if (match) {
                            deviceText = match[1].trim();
                        } else {
                            // If all fails, remove first 3 characters and hope for the best
                            deviceText = currentText.substring(3).trim();
                        }
                    }
                }
                
                // Update with new status indicator (paused takes priority)
                const statusIndicator = getStatusIndicator(status, pausedStatus);
                option.textContent = `${statusIndicator} ${deviceText}`;
                option.dataset.status = status;
                option.dataset.paused = pausedStatus;
                
            }
        });
    };
    
    // Save/load state to localStorage
    const saveState = () => {
        const state = {
            deviceId: currentDeviceId,
            timeRange: currentTimeRange
        };
        localStorage.setItem('monitoring_state', JSON.stringify(state));
    };
    
    const loadState = () => {
        try {
            const saved = localStorage.getItem('monitoring_state');
            if (saved) {
                const state = JSON.parse(saved);
                return state;
            }
        } catch (e) {
            console.error('Error loading state:', e);
        }
        return null;
    };
    
    // API helper
    const api = {
        _handleResponse: async (res) => {
            if (res.status === 401) {
                window.location.href = '/login';
                return {};
            }
            
            try {
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.message || `HTTP ${res.status}: ${res.statusText}`);
                }
                return data;
            } catch (error) {
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}: ${res.statusText}`);
                }
                throw error;
            }
        },
        
        get: async function(endpoint) {
            const res = await fetch(`${API_URL}/api/${endpoint}`);
            const result = await this._handleResponse(res);
            return result;
        },
        
        post: async function(endpoint, data) {
            const res = await fetch(`${API_URL}/api/${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });
            const result = await this._handleResponse(res);
            return result;
        }
    };
    
    // Initialize Socket.IO connection
    const initializeSocket = () => {
        socket = io();
        
        socket.on('connect', () => {
        });
        
        socket.on('disconnect', () => {
        });
        
        // Listen for ping updates
        socket.on('ping_update', (data) => {
            // Always update device status in cache and selector (lightweight operation)
            const deviceId = parseInt(data.device_id);
            const status = data.status; // Use status directly from ping result
            updateDeviceStatus(deviceId, status);
            
            // Only update charts if page is visible and this is the currently selected device
            if (document.visibilityState === 'visible' && data.device_id === currentDeviceId) {
                updatePingStatus(data);
                updatePingChart(data);
            }
        });
        
        // Listen for SNMP updates
        socket.on('snmp_update', (data) => {
            // Only process SNMP updates if page is visible
            if (document.visibilityState === 'visible') {
                const deviceId = data.device_id || data.id; // Support both formats
                if (deviceId === currentDeviceId) {
                    updateSNMPCharts(data.data || data);
                }
            }
        });
    };
    
    // Load devices into selector
    const loadDevices = async () => {
        try {
            const devices = await api.get('devices');
            
            // Use custom dropdown API
            if (window.customDeviceSelector) {
                window.customDeviceSelector.populateOptions(devices);
            } else {
                // Fallback for legacy compatibility
                deviceSelector.innerHTML = '<option value="">Vyberte zariadenie...</option>';
                
                devices.forEach(device => {
                    const option = document.createElement('option');
                    option.value = device.id;
                    
                    // Store original device info in data attributes for safe retrieval
                    option.setAttribute('data-name', device.name);
                    option.setAttribute('data-ip', device.ip);
                    option.setAttribute('data-paused', device.monitoring_paused ? 'true' : 'false');
                    
                    // Use device status from database or default to unknown
                    const status = device.status || 'unknown';
                    const isPaused = device.monitoring_paused;
                    
                    // Generate status indicator
                    let statusIndicator;
                    if (isPaused) {
                        statusIndicator = '⏸️'; // Pause symbol
                    } else {
                        switch (status) {
                            case 'online':
                                statusIndicator = '🟢'; // Green dot
                                break;
                            case 'offline':
                                statusIndicator = '🔴'; // Red dot
                                break;
                            default:
                                statusIndicator = '⚪'; // White dot for unknown
                        }
                    }
                    
                    option.textContent = `${statusIndicator} ${device.name} (${device.ip})`;
                    option.dataset.status = status;
                    option.dataset.paused = isPaused;
                    
                    deviceSelector.appendChild(option);
                });
            }
            
        } catch (error) {
            console.error('Chyba pri načítaní zariadení:', error);
        }
    };
    
    // Update ping status display - optimized version
    const updatePingStatus = (pingData) => {
        // Use cached DOM elements for better performance
        const pingStatus = domCache.pingStatus || document.getElementById('pingStatus');
        const avgLatency = domCache.avgLatency || document.getElementById('avgLatency');
        const packetLoss = domCache.packetLoss || document.getElementById('packetLoss');
        const lastPing = domCache.lastPing || document.getElementById('lastPing');
        
        if (!pingStatus) return; // Guard clause
        
        const isOnline = pingData.status === 'online';
        const indicator = pingStatus.querySelector('.ping-indicator');
        const statusText = pingStatus.querySelector('span');
        
        // Batch DOM updates using requestAnimationFrame
        requestAnimationFrame(() => {
            // Update status
            pingStatus.className = `ping-status ${pingData.status}`;
            if (indicator) indicator.className = `ping-indicator ${pingData.status}`;
            if (statusText) statusText.textContent = isOnline ? 'Online' : 'Offline';
            
            // Update metrics
            if (avgLatency) {
                avgLatency.textContent = pingData.avg_latency ? `${pingData.avg_latency.toFixed(1)} ms` : '-';
            }
            if (packetLoss) {
                packetLoss.textContent = `${pingData.packet_loss || 0}%`;
                
                // Update packet loss color
                const lossPercent = pingData.packet_loss || 0;
                if (lossPercent === 0) {
                    packetLoss.className = 'text-lg font-bold text-green-400';
                } else if (lossPercent < 10) {
                    packetLoss.className = 'text-lg font-bold text-yellow-400';
                } else {
                    packetLoss.className = 'text-lg font-bold text-red-400';
                }
            }
            if (lastPing) {
                lastPing.textContent = new Date(pingData.timestamp).toLocaleTimeString('sk-SK');
            }
        });
    };
    
    // Get time format configuration based on time range
    const getTimeFormats = (timeRange) => {
        switch (timeRange) {
            case '30m':
                return {
                    displayFormats: {
                        minute: 'HH:mm',
                        hour: 'HH:mm',
                        day: 'HH:mm'
                    },
                    tooltipFormat: 'dd/MM/yyyy HH:mm',
                    unit: 'minute',
                    stepSize: 10,
                    maxTicksLimit: 8
                };
            case '3h':
            case '6h':
            case '12h':
                return {
                    displayFormats: {
                        minute: 'HH:mm',
                        hour: 'HH:mm',
                        day: 'HH:mm'
                    },
                    tooltipFormat: 'dd/MM/yyyy HH:mm',
                    unit: 'hour',
                    stepSize: 1,
                    maxTicksLimit: 8
                };
            case '24h':
                return {
                    displayFormats: {
                        minute: 'HH:mm',
                        hour: 'dd/MM HH:mm',
                        day: 'dd/MM HH:mm'
                    },
                    tooltipFormat: 'dd/MM/yyyy HH:mm',
                    unit: 'hour',
                    stepSize: 2,
                    maxTicksLimit: 10
                };
            case '7d':
                return {
                    displayFormats: {
                        hour: 'dd/MM HH:mm',
                        day: 'dd/MM',
                        week: 'dd/MM'
                    },
                    tooltipFormat: 'dd/MM/yyyy HH:mm',
                    unit: 'day',
                    stepSize: 1,
                    maxTicksLimit: 8
                };
            case '30d':
                return {
                    displayFormats: {
                        day: 'dd/MM',
                        week: 'dd/MM',
                        month: 'MM/yy'
                    },
                    tooltipFormat: 'dd/MM/yyyy',
                    unit: 'day',
                    stepSize: 3,
                    maxTicksLimit: 12
                };
            case '90d':
                return {
                    displayFormats: {
                        day: 'dd/MM',
                        week: 'dd/MM',
                        month: 'MM/yy'
                    },
                    tooltipFormat: 'dd/MM/yyyy',
                    unit: 'day',
                    stepSize: 7,
                    maxTicksLimit: 14
                };
            case '1y':
                return {
                    displayFormats: {
                        day: 'dd/MM',
                        month: 'MM/yy',
                        year: 'yyyy'
                    },
                    tooltipFormat: 'dd/MM/yyyy',
                    unit: 'month',
                    stepSize: 1,
                    maxTicksLimit: 12
                };
            default:
                return {
                    displayFormats: {
                        minute: 'HH:mm',
                        hour: 'HH:mm',
                        day: 'dd/MM'
                    },
                    tooltipFormat: 'dd/MM/yyyy HH:mm',
                    unit: 'hour',
                    stepSize: 2,
                    maxTicksLimit: 8
                };
        }
    };

    // Initialize charts
    const initializeCharts = () => {
        
        const getChartOptions = (timeRange = currentTimeRange) => {
            const timeFormats = getTimeFormats(timeRange);
            
            return {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#d1d5db'
                        }
                    },
                    subtitle: {
                        display: true,
                        text: 'Kliknite a ťahajte pre zoom, reset tlačidlo pre návrat',
                        color: '#9ca3af',
                        font: {
                            size: 11,
                            style: 'italic'
                        },
                        padding: {
                            bottom: 10
                        }
                    }
                },
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            displayFormats: timeFormats.displayFormats,
                            tooltipFormat: timeFormats.tooltipFormat,
                            unit: timeFormats.unit,
                            stepSize: timeFormats.stepSize
                        },
                        ticks: {
                            color: '#9ca3af',
                            maxTicksLimit: timeFormats.maxTicksLimit || 8
                        },
                        grid: {
                            color: '#374151'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#9ca3af'
                        },
                        grid: {
                            color: '#374151'
                        }
                    }
                }
            };
        };

        // Smart Y-axis optimization function inspired by Uptime Kuma
        const optimizeYAxisRange = (data, chartType) => {
            if (!data || data.length === 0) {
                return { min: undefined, max: undefined, suggestedMin: undefined, suggestedMax: undefined };
            }

            // Extract Y values from data
            let values = [];
            if (Array.isArray(data)) {
                values = data.map(point => {
                    if (typeof point === 'object' && point !== null) {
                        return point.y !== undefined ? point.y : point;
                    }
                    return point;
                }).filter(val => val !== null && val !== undefined && !isNaN(val));
            }

            if (values.length === 0) {
                return { min: undefined, max: undefined, suggestedMin: undefined, suggestedMax: undefined };
            }

            const min = Math.min(...values);
            const max = Math.max(...values);
            const range = max - min;


            // Chart-specific optimizations
            switch (chartType) {
                case 'ping':
                    return optimizePingYAxis(min, max, range);
                case 'cpu':
                    return optimizeCpuYAxis(min, max, range);
                case 'temperature':
                    return optimizeTemperatureYAxis(min, max, range);
                case 'memory':
                    return optimizeMemoryYAxis(min, max, range);
                default:
                    return optimizeGenericYAxis(min, max, range);
            }
        };

        // Ping latency optimization - focus on actual latency range
        const optimizePingYAxis = (min, max, range) => {
            if (range === 0) {
                // Single value - create small range around it
                const padding = Math.max(min * 0.1, 0.1); // 10% padding or at least 0.1ms
                return {
                    suggestedMin: Math.max(0, min - padding),
                    suggestedMax: max + padding
                };
            }

            // For ping, we want to show the data centered with some breathing room
            // but avoid showing too much empty space at bottom
            let padding = range * 0.2; // 20% padding on each side
            let suggestedMin = Math.max(0, min - padding);
            let suggestedMax = max + padding;

            // Don't start too close to zero if all pings are much higher
            // This prevents the chart from being squashed at the top
            if (min > 1 && range > 0.5) {
                // If lowest ping is above 1ms and there's reasonable variation
                suggestedMin = Math.max(0, min - range * 0.4);
            } else if (min > 0.5 && range < 0.3) {
                // Stable but higher latency - center better
                suggestedMin = Math.max(0, min - 0.3);
                suggestedMax = max + 0.3;
            }

            return {
                suggestedMin: suggestedMin,
                suggestedMax: suggestedMax
            };
        };

        // CPU optimization - usually 0-100% but optimize based on actual usage
        const optimizeCpuYAxis = (min, max, range) => {
            // Always start from 0 for CPU percentage, but adjust max intelligently
            if (max <= 50) {
                // Low CPU usage - don't show full 100%
                return {
                    min: 0,
                    suggestedMax: Math.min(100, Math.max(50, max * 1.2))
                };
            } else if (max <= 80) {
                // Medium CPU usage
                return {
                    min: 0,
                    suggestedMax: Math.min(100, max * 1.15)
                };
            } else {
                // High CPU usage - show full scale
                return {
                    min: 0,
                    max: 100
                };
            }
        };

        // Temperature optimization - center around actual temperature range
        const optimizeTemperatureYAxis = (min, max, range) => {
            if (range === 0) {
                // Constant temperature - create range around it
                const padding = 5; // 5°C padding
                return {
                    suggestedMin: Math.max(0, min - padding),
                    suggestedMax: max + padding
                };
            }

            // For temperature, center the data better
            const padding = Math.max(range * 0.15, 3); // At least 3°C padding, 15% of range
            let suggestedMin = Math.max(0, min - padding);
            let suggestedMax = max + padding;

            // If temperature is consistently high (like 60°C), don't start from 0
            if (min > 30 && range < 15) {
                // High stable temperature - optimize range to center the data
                suggestedMin = Math.max(0, min - Math.max(range * 0.5, 5));
                suggestedMax = max + Math.max(range * 0.5, 5);
            }

            return {
                suggestedMin: suggestedMin,
                suggestedMax: suggestedMax
            };
        };

        // Memory optimization - show actual usage range
        const optimizeMemoryYAxis = (min, max, range) => {
            // For memory, always start from 0 but optimize max
            const suggestedMax = max * 1.1; // 10% padding above max

            return {
                min: 0,
                suggestedMax: suggestedMax
            };
        };

        // Generic optimization for other chart types
        const optimizeGenericYAxis = (min, max, range) => {
            if (range === 0) {
                const padding = Math.max(Math.abs(min) * 0.1, 1);
                return {
                    suggestedMin: min - padding,
                    suggestedMax: max + padding
                };
            }

            const padding = range * 0.1;
            return {
                suggestedMin: min - padding,
                suggestedMax: max + padding
            };
        };

        // Apply Y-axis optimization to a chart
        const applyYAxisOptimization = (chart, chartType) => {
            if (!chart || !chart.data || !chart.data.datasets) {
                return;
            }

            let data = [];
            
            // For memory chart, combine data from both datasets (used and total memory)
            if (chartType === 'memory' && chart.data.datasets.length >= 2) {
                // Combine used and total memory values for optimization
                const usedData = chart.data.datasets[0].data || [];
                const totalData = chart.data.datasets[1].data || [];
                data = [...usedData, ...totalData];
            } else if (chart.data.datasets[0]) {
                data = chart.data.datasets[0].data || [];
            }

            const optimization = optimizeYAxisRange(data, chartType);

            if (optimization && (optimization.min !== undefined || optimization.max !== undefined || 
                optimization.suggestedMin !== undefined || optimization.suggestedMax !== undefined)) {
                
                // Apply optimization to Y-axis
                Object.assign(chart.options.scales.y, optimization);
                
                
                // Update chart to apply new axis settings
                chart.update('none');
            }
        };

        // Export Y-axis optimization function to global scope
        window.applyYAxisOptimization = applyYAxisOptimization;

        // Periodically optimize all chart Y-axes (for real-time data)
        const optimizeAllChartsYAxes = () => {
            if (charts.ping) applyYAxisOptimization(charts.ping, 'ping');
            if (charts.cpu) applyYAxisOptimization(charts.cpu, 'cpu');
            if (charts.temperature) applyYAxisOptimization(charts.temperature, 'temperature');
            if (charts.memory) applyYAxisOptimization(charts.memory, 'memory');
        };

        // Export Y-axis optimization functions to global scope
        window.optimizeAllChartsYAxes = optimizeAllChartsYAxes;

        // Set up periodic Y-axis optimization for real-time data (every 30 seconds)
        let yAxisOptimizationInterval = null;
        const startYAxisOptimization = () => {
            if (yAxisOptimizationInterval) {
                clearInterval(yAxisOptimizationInterval);
            }
            
            // Only start optimization if page is visible and device is selected
            if (document.visibilityState === 'visible' && currentDeviceId) {
                yAxisOptimizationInterval = setInterval(() => {
                    // Double-check page visibility before optimizing
                    if (document.visibilityState === 'visible' && currentDeviceId) {
                        optimizeAllChartsYAxes();
                    } else {
                        // Stop optimization if page became hidden or device deselected
                        stopYAxisOptimization();
                    }
                }, 30000); // 30 seconds
            }
        };

        const stopYAxisOptimization = () => {
            if (yAxisOptimizationInterval) {
                clearInterval(yAxisOptimizationInterval);
                yAxisOptimizationInterval = null;
            }
        };

        // Export Y-axis optimization functions to global scope
        window.startYAxisOptimization = startYAxisOptimization;
        window.stopYAxisOptimization = stopYAxisOptimization;
        
        // Page Visibility API - handle tab visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                // Page became visible - restart optimizations and refresh data if device selected
                if (currentDeviceId) {
                    startYAxisOptimization();
                    // Refresh current device data to get latest updates
                    loadHistoricalData(currentDeviceId);
                }
            } else {
                // Page became hidden - stop optimizations to save CPU
                stopYAxisOptimization();
            }
        });

        const chartOptions = getChartOptions();
        
        // Ping Chart
        charts.ping = new Chart(document.getElementById('pingChart'), {
            type: 'line',
            data: {
                datasets: [{
                    label: 'Ping Latencia (ms)',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.1,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 0,  // Completely disable hover points
                    borderWidth: 2
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    ...chartOptions.scales,
                    y: {
                        ...chartOptions.scales.y,
                        beginAtZero: false, // Let optimization handle this
                        title: {
                            display: true,
                            text: 'Latencia (ms)',
                            color: '#d1d5db'
                        }
                    }
                }
            }
        });
        
        // CPU Chart
        charts.cpu = new Chart(document.getElementById('cpuChart'), {
            type: 'line',
            data: {
                datasets: [{
                    label: 'CPU Load (%)',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.1,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 0,  // Completely disable hover points
                    borderWidth: 2,
                    spanGaps: true,  // Connect points even if there are gaps
                    showLine: true   // Ensure line is always shown
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    ...chartOptions.scales,
                    y: {
                        ...chartOptions.scales.y,
                        beginAtZero: false, // Let optimization handle this
                        title: {
                            display: true,
                            text: 'CPU Load (%)',
                            color: '#d1d5db'
                        }
                    }
                }
            }
        });
        
        // Temperature Chart
        charts.temperature = new Chart(document.getElementById('temperatureChart'), {
            type: 'line',
            data: {
                datasets: [{
                    label: 'Teplota (°C)',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.1,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 0,  // Completely disable hover points
                    borderWidth: 2,
                    spanGaps: true,  // Connect points even if there are gaps
                    showLine: true   // Ensure line is always shown
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    ...chartOptions.scales,
                    y: {
                        ...chartOptions.scales.y,
                        beginAtZero: false, // Let optimization handle this
                        title: {
                            display: true,
                            text: 'Teplota (°C)',
                            color: '#d1d5db'
                        }
                    }
                }
            }
        });
        
        // Availability Chart (removed - replaced by Memory Chart)
        // charts.availability = ...

        // Memory Usage Chart (Simple Lines with Subtle Fill)
        charts.memory = new Chart(document.getElementById('memoryChart'), {
            type: 'line',
            data: {
                datasets: [
                    {
                        label: 'Used Memory',
                        data: [],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.15)',
                        fill: true,
                        tension: 0.1,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHoverRadius: 0,  // Completely disable hover points
                        spanGaps: true,  // Connect points even if there are gaps
                        showLine: true   // Ensure line is always shown
                    },
                    {
                        label: 'Total Memory',
                        data: [],
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.1,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHoverRadius: 0,  // Completely disable hover points
                        spanGaps: true,  // Connect points even if there are gaps
                        showLine: true   // Ensure line is always shown
                    }
                ]
            },
            options: {
                ...chartOptions,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    ...chartOptions.plugins,
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: '#1f2937',
                        titleColor: '#f3f4f6',
                        bodyColor: '#d1d5db',
                        borderColor: '#374151',
                        borderWidth: 1,
                        callbacks: {
                            label: function(context) {
                                const datasetLabel = context.dataset.label;
                                const value = context.parsed.y;
                                return `${datasetLabel}: ${value.toFixed(0)} MB`;
                            },
                            afterBody: function(context) {
                                if (context.length >= 2) {
                                    const usedMemory = context[0].parsed.y;
                                    const totalMemory = context[1].parsed.y;
                                    const freeMemory = totalMemory - usedMemory;
                                    const usagePercent = ((usedMemory / totalMemory) * 100).toFixed(1);
                                    return [
                                        `Free Memory: ${freeMemory.toFixed(0)} MB`,
                                        `Memory Usage: ${usagePercent}%`
                                    ];
                                }
                                return [];
                            }
                        }
                    }
                },
                scales: {
                    x: chartOptions.scales.x,
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Memory (MB)',
                            color: '#d1d5db'
                        },
                        grid: {
                            color: '#374151'
                        },
                        ticks: {
                            color: '#d1d5db'
                        }
                    }
                }
            }
        });
        
        // Add custom zoom functionality to all charts
        Object.values(charts).forEach(chart => {
            if (chart && typeof addCustomZoom === 'function') {
                addCustomZoom(chart);
            }
        });
        

        // Nastaviť mobilné správanie tooltipov (zabrániť "zaseknutiu")
        setupMobileTooltipDismiss();
    };

    // Pomocná funkcia: skryť všetky tooltippy na všetkých grafoch
    const hideAllChartTooltips = () => {
        if (!charts) return;
        Object.values(charts).forEach(ch => {
            if (ch && ch.tooltip && typeof ch.tooltip.setActiveElements === 'function') {
                ch.tooltip.setActiveElements([], { x: 0, y: 0 });
                try { ch.update(); } catch (_) {}
            }
        });
    };

    // Inicializácia listenerov pre mobil – druhé ťuknutie alebo ťuk mimo graf skryje tooltip
    const setupMobileTooltipDismiss = () => {
        if (!("ontouchstart" in window)) return; // len mobil / touch zariadenia
        if (window._mobileTooltipHandlersAdded) return; // zabráni duplicite pri re-init
        window._mobileTooltipHandlersAdded = true;

        // Tap mimo grafik – schovať všetko
        document.addEventListener('touchstart', (e) => {
            if (!e.target.closest('.chart-container')) {
                hideAllChartTooltips();
            }
        }, { passive: true });

        // Tap vnútri konkrétneho grafu ale nie na dátový bod – schovať (toggle)
        Object.values(charts).forEach(ch => {
            if (!ch || !ch.canvas) return;
            const canvas = ch.canvas;
            canvas.addEventListener('touchstart', (evt) => {
                // Zistíme, či je aktuálne aktívny tooltip
                const hasActive = ch.tooltip && ch.tooltip.getActiveElements && ch.tooltip.getActiveElements().length > 0;
                // Zistíme, či je pod dotykom nejaký element dát
                let elementsAtPoint = [];
                try {
                    elementsAtPoint = ch.getElementsAtEventForMode(evt, 'nearest', { intersect: false }, true) || [];
                } catch (_) {}
                // Ak tooltip je aktívny a teraz ťuk nemá žiadny dátový bod -> schovať (toggle)
                if (hasActive && elementsAtPoint.length === 0) {
                    hideAllChartTooltips();
                }
            }, { passive: true });
        });

        // Voliteľné auto‑skrytie po čase (napr. 6s) ak zostane visieť
        document.addEventListener('touchend', () => {
            if (window._mobileTooltipAutoHideTimer) clearTimeout(window._mobileTooltipAutoHideTimer);
            window._mobileTooltipAutoHideTimer = setTimeout(() => {
                hideAllChartTooltips();
            }, 6000);
        }, { passive: true });
    };
    
    // Update ping chart with new data
    const updatePingChart = (pingData) => {
        if (typeof addDebugLog === 'function') {
            if (pingData.history && Array.isArray(pingData.history)) {
                addDebugLog(`📈 updatePingChart: ${pingData.history.length} historických bodov`);
            } else {
                addDebugLog(`📈 updatePingChart: real-time bod`);
            }
        }
        
        if (!charts.ping) return;
        
        const chart = charts.ping;
        
        // Check if this is historical data (array) or real-time data (single point)
        if (pingData.history && Array.isArray(pingData.history)) {
            
            // Prepare data array for batch processing
            const pingPoints = [];
            
            // Single pass through data
            pingData.history.forEach(point => {
                if (point.avg_latency !== null && point.timestamp) {
                    pingPoints.push({
                        x: new Date(point.timestamp),
                        y: point.avg_latency
                    });
                }
            });
            
            // Batch update using requestAnimationFrame
            requestAnimationFrame(() => {
                chart.data.datasets[0].data = pingPoints;
                
                // Apply Y-axis optimization for ping chart
                applyYAxisOptimization(chart, 'ping');
                
                chart.update('none');
                
                // Apply full time range horizon after historical data update
                if (typeof window.applyFullTimeRangeToAllCharts === 'function') {
                    // Use setTimeout to apply after chart update
                    setTimeout(() => {
                        if (typeof window.applyFullTimeRangeToChart === 'function') {
                            window.applyFullTimeRangeToChart(chart);
                        }
                    }, 50);
                }
            });
            
        } else {
            // Real-time single data point - lightweight update
            const now = new Date(pingData.timestamp);
            
            requestAnimationFrame(() => {
                // Add new data point
                if (pingData.avg_latency !== null) {
                    chart.data.datasets[0].data.push({
                        x: now,
                        y: pingData.avg_latency
                    });
                }
                
                // Keep only reasonable amount of real-time data
                if (chart.data.datasets[0].data.length > 1000) {
                    chart.data.datasets[0].data.shift();
                }
                
                chart.update('none');
            });
        }
    };
    
    // Dynamic point size adjustment based on data density and time range
    const adjustPointSizes = (chart, dataLength, timeRange = currentTimeRange) => {
        if (!chart || !chart.data || !chart.data.datasets) return;
        
        // Apply to all datasets - always clean line charts with no visible points
        chart.data.datasets.forEach(dataset => {
            dataset.pointRadius = 0;           // Never show points
            dataset.pointHoverRadius = 0;      // Never show hover points either
            
            // Ensure lines are visible especially for Recent interval
            if (!dataset.borderWidth || dataset.borderWidth < 2) {
                dataset.borderWidth = 2;
            }
            
            // Ensure line tension for smooth curves
            if (dataset.tension === undefined) {
                dataset.tension = 0.1;
            }
            
            // Ensure lines are always shown even with few points
            dataset.showLine = true;
            dataset.spanGaps = true;
        });
    };

    // Update SNMP charts
    const updateSNMPCharts = (snmpData) => {
        if (typeof addDebugLog === 'function') {
            if (snmpData.history && Array.isArray(snmpData.history)) {
                addDebugLog(`📊 updateSNMPCharts: ${snmpData.history.length} historických SNMP bodov`);
            } else {
                addDebugLog(`📊 updateSNMPCharts: real-time SNMP bod`);
            }
        }
        
        // Check if this is historical data (array) or real-time data (single point)  
        if (snmpData.history && Array.isArray(snmpData.history)) {
            // Prepare data arrays for batch processing
            const cpuData = [];
            const tempData = [];
            const usedMemData = [];
            const totalMemData = [];
            let cpuCount = 0;
            let tempCount = 0;
            let memoryCount = 0;
            let lastTotalMem = null; // Forward-fill for Total Memory
            
            // Single pass through data for all charts
            snmpData.history.forEach(point => {
                if (point.timestamp) {
                    const timestamp = new Date(point.timestamp);
                    if (!isNaN(timestamp.getTime())) {
                        // CPU data
                        if (point.cpu_load !== null && point.cpu_load !== undefined) {
                            cpuData.push({
                                x: timestamp,
                                y: parseFloat(point.cpu_load)
                            });
                            cpuCount++;
                        }
                        
                        // Temperature data
                        if (point.temperature !== null && point.temperature !== undefined) {
                            tempData.push({
                                x: timestamp,
                                y: parseFloat(point.temperature)
                            });
                            tempCount++;
                        }

                        // Memory data (v MB) - process independently to avoid truncation
                        if (point.used_memory !== null && point.used_memory !== undefined) {
                            const usedMem = parseFloat(point.used_memory);
                            if (!isNaN(usedMem)) {
                                // Dataset 0: Used Memory (red line)
                                usedMemData.push({
                                    x: timestamp,
                                    y: usedMem
                                });
                                memoryCount++;
                            }
                        }
                        
                        // Total Memory with forward-fill to prevent truncation
                        if (point.total_memory !== null && point.total_memory !== undefined) {
                            const totalMem = parseFloat(point.total_memory);
                            if (!isNaN(totalMem)) {
                                lastTotalMem = totalMem;
                                // Dataset 1: Total Memory (blue line)
                                totalMemData.push({
                                    x: timestamp,
                                    y: totalMem
                                });
                            }
                        } else if (lastTotalMem !== null && point.used_memory !== null && point.used_memory !== undefined) {
                            // Forward-fill: use last known Total Memory value when used_memory is present but total_memory is missing
                            totalMemData.push({
                                x: timestamp,
                                y: lastTotalMem
                            });
                        }
                    } else {
                        console.warn('Invalid timestamp for SNMP data:', point.timestamp);
                    }
                }
            });
            
            // Batch update charts using requestAnimationFrame for smooth UI
            requestAnimationFrame(() => {
                // Update CPU chart
                if (charts.cpu && cpuData.length > 0) {
                    charts.cpu.data.datasets[0].data = cpuData;
                    adjustPointSizes(charts.cpu, cpuData.length, currentTimeRange);
                    applyYAxisOptimization(charts.cpu, 'cpu');
                    charts.cpu.update('none');
                } else if (charts.cpu) {
                    charts.cpu.data.datasets[0].data = [];
                    charts.cpu.update('none');
                }
                
                // Update temperature chart
                if (charts.temperature && tempData.length > 0) {
                    charts.temperature.data.datasets[0].data = tempData;
                    adjustPointSizes(charts.temperature, tempData.length, currentTimeRange);
                    applyYAxisOptimization(charts.temperature, 'temperature');
                    charts.temperature.update('none');
                } else if (charts.temperature) {
                    charts.temperature.data.datasets[0].data = [];
                    charts.temperature.update('none');
                }

                // Update memory chart (independent datasets)
                if (charts.memory && (usedMemData.length > 0 || totalMemData.length > 0)) {
                    charts.memory.data.datasets[0].data = usedMemData;  // Used Memory (red line)
                    charts.memory.data.datasets[1].data = totalMemData;  // Total Memory (blue line)
                    
                    // Update lastTotalMemoryValue for real-time forward-fill
                    if (totalMemData.length > 0) {
                        lastTotalMemoryValue = totalMemData[totalMemData.length - 1].y;
                    }
                    
                    adjustPointSizes(charts.memory, Math.max(usedMemData.length, totalMemData.length), currentTimeRange);
                    applyYAxisOptimization(charts.memory, 'memory');
                    charts.memory.update('none');
                } else if (charts.memory) {
                    charts.memory.data.datasets[0].data = [];
                    charts.memory.data.datasets[1].data = [];
                    charts.memory.update('none');
                }
                
                // Apply full time range horizon after historical data update  
                if (typeof window.applyFullTimeRangeToAllCharts === 'function') {
                    // Use setTimeout to apply after all charts update
                    setTimeout(() => {
                        window.applyFullTimeRangeToAllCharts();
                    }, 50);
                }
            });
            
        } else {
            // Real-time single data point - lightweight update
            const now = new Date();
            
            // Update device model and RouterOS version if available
            if ((snmpData.board_name && snmpData.board_name !== 'N/A') || (snmpData.version && snmpData.version !== 'N/A')) {
                const deviceModel = domCache.deviceModel || document.getElementById('deviceModel');
                if (deviceModel) {
                    let modelText = '';
                    if (snmpData.board_name && snmpData.board_name !== 'N/A') {
                        modelText = snmpData.board_name;
                    }
                    if (snmpData.version && snmpData.version !== 'N/A') {
                        if (modelText) {
                            modelText += ` - RouterOS ${snmpData.version}`;
                        } else {
                            modelText = `RouterOS ${snmpData.version}`;
                        }
                    }
                    if (modelText) {
                        deviceModel.textContent = modelText;
                    }
                }
            }
            
            requestAnimationFrame(() => {
                // Update CPU chart
                if (charts.cpu && snmpData.cpu_load !== undefined) {
                    charts.cpu.data.datasets[0].data.push({
                        x: now,
                        y: parseFloat(snmpData.cpu_load)
                    });
                    
                    // Keep only reasonable amount of real-time data
                    if (charts.cpu.data.datasets[0].data.length > 1000) {
                        charts.cpu.data.datasets[0].data.shift();
                    }
                    
                    charts.cpu.update('none');
                }
                
                // Update temperature chart
                if (charts.temperature && snmpData.temperature !== undefined) {
                    charts.temperature.data.datasets[0].data.push({
                        x: now,
                        y: parseFloat(snmpData.temperature)
                    });
                    
                    // Keep only reasonable amount of real-time data
                    if (charts.temperature.data.datasets[0].data.length > 1000) {
                        charts.temperature.data.datasets[0].data.shift();
                    }
                    
                    charts.temperature.update('none');
                }

                // Update memory chart (independent datasets for real-time)
                if (charts.memory) {
                    let memoryUpdated = false;
                    
                    // Update Used Memory if available
                    if (snmpData.used_memory !== undefined) {
                        const usedMem = parseFloat(snmpData.used_memory);
                        if (!isNaN(usedMem)) {
                            charts.memory.data.datasets[0].data.push({
                                x: now,
                                y: usedMem
                            });
                            memoryUpdated = true;
                        }
                    }
                    
                    // Update Total Memory if available, or forward-fill if used memory is present
                    if (snmpData.total_memory !== undefined) {
                        const totalMem = parseFloat(snmpData.total_memory);
                        if (!isNaN(totalMem)) {
                            lastTotalMemoryValue = totalMem;
                            charts.memory.data.datasets[1].data.push({
                                x: now,
                                y: totalMem
                            });
                            memoryUpdated = true;
                        }
                    } else if (lastTotalMemoryValue !== null && snmpData.used_memory !== undefined) {
                        // Forward-fill: use last known Total Memory when used_memory is present but total_memory is missing
                        charts.memory.data.datasets[1].data.push({
                            x: now,
                            y: lastTotalMemoryValue
                        });
                        memoryUpdated = true;
                    }
                    
                    if (memoryUpdated) {
                        // Keep only reasonable amount of real-time data for both datasets
                        if (charts.memory.data.datasets[0].data.length > 1000) {
                            charts.memory.data.datasets[0].data.shift();
                        }
                        if (charts.memory.data.datasets[1].data.length > 1000) {
                            charts.memory.data.datasets[1].data.shift();
                        }
                        
                        charts.memory.update('none');
                    }
                }
            });
        }
    };
    
    // Update availability chart with new data - REMOVED (replaced by Memory Chart)
    /*
    const updateAvailabilityChart = async (deviceId) => {
        if (!charts.availability) return;
        
        
        try {
            const response = await fetch(`/api/monitoring/availability/${deviceId}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const availabilityData = await response.json();
            
            if (Array.isArray(availabilityData) && availabilityData.length > 0) {
                const labels = availabilityData.map(item => item.date);
                const data = availabilityData.map(item => item.percentage);
                
                charts.availability.data.labels = labels;
                charts.availability.data.datasets[0].data = data;
                charts.availability.update('resize');
                
            } else {
                // Clear chart if no data
                charts.availability.data.labels = [];
                charts.availability.data.datasets[0].data = [];
                charts.availability.update('none');
            }
            
        } catch (error) {
            console.error('Error loading availability data:', error);
            // Clear chart on error
            if (charts.availability) {
                charts.availability.data.labels = [];
                charts.availability.data.datasets[0].data = [];
                charts.availability.update('none');
            }
        }
    };
    */
    
    // Helper function to get time range in milliseconds (used for animation direction)
    const getTimeRangeMs = (timeRange) => {
        switch (timeRange) {
            case 'recent': return 30 * 60 * 1000; // 30 minutes
            case '3h': return 3 * 60 * 60 * 1000;
            case '6h': return 6 * 60 * 60 * 1000;
            case '12h': return 12 * 60 * 60 * 1000;
            case '24h': return 24 * 60 * 60 * 1000;
            case '7d': return 7 * 24 * 60 * 60 * 1000;
            case '30d': return 30 * 24 * 60 * 60 * 1000;
            case '90d': return 90 * 24 * 60 * 60 * 1000;
            case '1y': return 365 * 24 * 60 * 60 * 1000;
            default: return 24 * 60 * 60 * 1000; // default 24h
        }
    };
    
    // Animate zoom-in effect (shrinking time range)
    const animateZoomIn = (charts) => {
        Object.values(charts).forEach(chart => {
            if (chart && chart.canvas) {
                // Add CSS animation class for zoom-in
                chart.canvas.style.transform = 'scale(1.05)';
                chart.canvas.style.transition = 'transform 0.3s ease-out';
                
                setTimeout(() => {
                    chart.canvas.style.transform = 'scale(1)';
                    setTimeout(() => {
                        chart.canvas.style.transition = '';
                    }, 300);
                }, 50);
            }
        });
    };
    
    // Animate zoom-out effect (expanding time range)
    const animateZoomOut = (charts) => {
        Object.values(charts).forEach(chart => {
            if (chart && chart.canvas) {
                // Add CSS animation class for zoom-out
                chart.canvas.style.transform = 'scale(0.95)';
                chart.canvas.style.transition = 'transform 0.3s ease-out';
                
                setTimeout(() => {
                    chart.canvas.style.transform = 'scale(1)';
                    setTimeout(() => {
                        chart.canvas.style.transition = '';
                    }, 300);
                }, 50);
            }
        });
    };
    
    // Apply smooth transition animation based on time range direction
    const applyTimeRangeTransition = async (oldTimeRange, newTimeRange) => {
        const oldMs = getTimeRangeMs(oldTimeRange);
        const newMs = getTimeRangeMs(newTimeRange);
        
        
        // Reset zoom on all charts first
        if (typeof resetAllChartsZoom === 'function') {
            resetAllChartsZoom();
        }
        
        // Wait a moment for zoom reset to complete
        await new Promise(resolve => setTimeout(resolve, 50));
        
        // CRITICAL: Apply correct time formats for the new time range
        // This ensures that time axes show proper labels for each interval
        if (typeof window.applyFullTimeRangeToAllCharts === 'function') {
            window.applyFullTimeRangeToAllCharts();
        }
        
        // Wait a moment for time format update to complete
        await new Promise(resolve => setTimeout(resolve, 50));
        
        if (newMs < oldMs) {
            // Zooming in (shorter time range)
            animateZoomIn(charts);
        } else if (newMs > oldMs) {
            // Zooming out (longer time range)
            animateZoomOut(charts);
        } else {
            // Same range, no animation needed
        }
    };
    
    // Get time range from buttons instead of selector
    const getSelectedTimeRange = () => {
        // Ak je aktívny single chart zoom-out, použij currentTimeRange namiesto UI
        if (window._singleChartZoomOut) {
            return window.currentTimeRange;
        }
        
        const activeBtn = document.querySelector('.time-range-btn.active');
        const range = activeBtn ? activeBtn.dataset.range : currentTimeRange;
        return range;
    };
    
    // Set active time range button
    const setActiveTimeRange = (timeRange) => {
        // Check if global time range changes are blocked during single chart expansion
        if (window._blockGlobalTimeRangeChanges) {
            if (typeof addDebugLog === 'function') {
                addDebugLog(`🚫 setActiveTimeRange blokovaný - window._blockGlobalTimeRangeChanges = true`);
            }
            return;
        }
        
        if (typeof addDebugLog === 'function') {
            addDebugLog(`🔧 setActiveTimeRange pokračuje - nastavujem ${timeRange}`);
        }
        
        // Remove active class from all buttons
        document.querySelectorAll('.time-range-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        
        // Add active class to selected button
        const targetBtn = document.querySelector(`[data-range="${timeRange}"]`);
        if (targetBtn) {
            targetBtn.classList.add('active');
        }
        
        if (typeof addDebugLog === 'function') {
            addDebugLog(`🎯 setActiveTimeRange: Tlačidlo nastavené na active`);
        }
        
        currentTimeRange = timeRange;
        window.currentTimeRange = timeRange; // Export for zoom functionality
        
        if (typeof addDebugLog === 'function') {
            addDebugLog(`📝 setActiveTimeRange: Premenné nastavené`);
        }
        
        // Update time formatting for all charts
        if (typeof addDebugLog === 'function') {
            addDebugLog(`⏰ setActiveTimeRange: Volám updateChartTimeFormats`);
        }
        updateChartTimeFormats(timeRange);
        
        if (typeof addDebugLog === 'function') {
            addDebugLog(`💾 setActiveTimeRange: Volám saveState`);
        }
        saveState();
        
        if (typeof addDebugLog === 'function') {
            addDebugLog(`✨ setActiveTimeRange: Dokončené pre ${timeRange}`);
        }
    };

    // Update time formatting for all charts based on time range
    const updateChartTimeFormats = (timeRange) => {
        if (typeof addDebugLog === 'function') {
            addDebugLog(`📅 updateChartTimeFormats: Začínam pre ${timeRange}`);
        }
        
        try {
            const timeFormats = getTimeFormats(timeRange);
            
            if (typeof addDebugLog === 'function') {
                addDebugLog(`📊 updateChartTimeFormats: Získané formáty pre ${timeRange}`);
            }
            
            // Update all existing charts with new time formats and point sizes
            Object.values(charts).forEach(chart => {
                if (chart && chart.options && chart.options.scales && chart.options.scales.x) {
                chart.options.scales.x.time.displayFormats = timeFormats.displayFormats;
                chart.options.scales.x.time.tooltipFormat = timeFormats.tooltipFormat;
                chart.options.scales.x.time.unit = timeFormats.unit;
                chart.options.scales.x.time.stepSize = timeFormats.stepSize;
                
                // Update maxTicksLimit
                if (chart.options.scales.x.ticks) {
                    chart.options.scales.x.ticks.maxTicksLimit = timeFormats.maxTicksLimit || 8;
                }
                
                // Update point sizes based on new time range
                if (chart.data && chart.data.datasets && chart.data.datasets[0] && chart.data.datasets[0].data) {
                    const dataLength = chart.data.datasets[0].data.length;
                    adjustPointSizes(chart, dataLength, timeRange);
                }
                
                chart.update('none');
            }
        });
        
        if (typeof addDebugLog === 'function') {
            addDebugLog(`✅ updateChartTimeFormats: Dokončené pre ${timeRange}`);
        }
        
        
        } catch (error) {
            if (typeof addDebugLog === 'function') {
                addDebugLog(`❌ updateChartTimeFormats chyba: ${error.message}`);
            }
            console.error('Error in updateChartTimeFormats:', error);
        }
    };
    
    // Update chart titles with current time range
    const updateChartTitles = (timeRange) => {
        const timeRangeLabels = {
            'recent': 'Posledná hodina',
            '30m': 'Posledných 30 minút',
            '3h': 'Posledné 3 hodiny',
            '6h': 'Posledných 6 hodín',
            '12h': 'Posledných 12 hodín', 
            '24h': 'Posledných 24 hodín',
            '7d': 'Posledných 7 dní',
            '30d': 'Posledných 30 dní',
            '90d': 'Posledných 90 dní',
            '1y': 'Posledný rok'
        };
        
        const label = timeRangeLabels[timeRange] || 'Posledných 24 hodín';
        
        // Update chart subtitles - find them by their position in the card
        const chartCards = document.querySelectorAll('.card');
        chartCards.forEach(card => {
            // Look for chart container inside this card
            const chartContainer = card.querySelector('.chart-container');
            if (chartContainer) {
                // Find the subtitle in this card - it's the .text-gray-400 element
                const subtitle = card.querySelector('.text-gray-400');
                if (subtitle) {
                    // Don't update availability chart (it always shows "Posledných 7 dní")
                    const isAvailabilityChart = card.textContent.includes('Availability');
                    if (!isAvailabilityChart) {
                        subtitle.textContent = label;
                    }
                }
            }
        });
    };
    
    // Add chart loading animation - optimized version
    const addChartLoadingAnimation = () => {
        // Use cached DOM elements if available, fallback to query
        const containers = domCache.chartContainers || document.querySelectorAll('.chart-container');
        
        // Batch DOM operations using requestAnimationFrame
        requestAnimationFrame(() => {
            containers.forEach(container => {
                container.classList.add('updating');
            });
            
            // Remove updating class and add fade-in effect
            setTimeout(() => {
                requestAnimationFrame(() => {
                    containers.forEach(container => {
                        container.classList.remove('updating');
                        container.classList.add('chart-fade-in');
                    });
                    
                    // Clean up fade-in class
                    setTimeout(() => {
                        requestAnimationFrame(() => {
                            containers.forEach(container => {
                                container.classList.remove('chart-fade-in');
                            });
                        });
                    }, 800);
                });
            }, 300);
        });
    };
    
    // Load historical data with animation
    const loadHistoricalData = async (deviceId, showLoadingAnimation = true) => {
        if (typeof addDebugLog === 'function') {
            addDebugLog(`🚀 loadHistoricalData zavolané pre device: ${deviceId}, showLoadingAnimation: ${showLoadingAnimation}`);
        }
        
        if (isLoadingData) {
            if (typeof addDebugLog === 'function') {
                addDebugLog(`⏸️ Načítanie preskočené - už prebieha pre iné zariadenie`);
            }
            return; // Prevent multiple simultaneous requests
        }
        
        isLoadingData = true;
        
        try {
            const timeRange = getSelectedTimeRange();
            
            if (typeof addDebugLog === 'function') {
                addDebugLog(`📅 Aktuálny časový rozsah: ${timeRange}`);
            }
            
            // Pre prvé načítanie použijeme kratší rozsah pre rýchlejšie načítanie
            // VÝNIMKA: ak je aktívny zoom-out alebo single chart expansion, načítaj všetky dáta
            let optimizedRange = timeRange;
            
            // Pre single chart zoom-out VŽDY použijeme plný rozsah - bez akejkoľvek optimalizácie
            if (window._singleChartZoomOut || window._isZoomOutExpansion) {
                optimizedRange = timeRange;
            } else if ((timeRange === '24h' || timeRange === '7d' || timeRange === '30d')) {
                // Pri prvom načítaní použijeme Recent (1 hodina) pre rýchlejší start
                const hasData = charts.ping && charts.ping.data.datasets[0].data.length > 0;
                if (!hasData) {
                    optimizedRange = 'recent';
                }
            }
            
            // Add loading animation only when requested (e.g., manual refresh, not time range changes)
            if (showLoadingAnimation) {
                addChartLoadingAnimation();
            }
            
            // Update chart titles (ale zobrazíme správny label pre pôvodný range)
            updateChartTitles(timeRange);
            // Map frontend range names to backend range names
            const apiRange = optimizedRange === '30m' ? 'recent' : optimizedRange;
            
            // Upravená URL pre nový API endpoint - bez 'monitoring/' prefix
            const apiUrl = `api/monitoring/history/${deviceId}?range=${apiRange}`;
            
            if (typeof addDebugLog === 'function') {
                addDebugLog(`🌐 API volanie: /${apiUrl}`);
                addDebugLog(`📋 Mapovanie rozsahu: ${optimizedRange} → ${apiRange}`);
            }
            
            // Fetch s timeout pre rýchlejšie error handling
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout
            
            const response = await fetch(`/${apiUrl}`, {
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            
            if (typeof addDebugLog === 'function') {
                addDebugLog(`📡 API odpoveď status: ${response.status} ${response.ok ? '✅' : '❌'}`);
            }
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (typeof addDebugLog === 'function') {
                addDebugLog(`📦 API dáta prijaté, status: ${data.status}`);
                addDebugLog(`📊 Ping záznamov: ${data.ping_data?.length || 0}, SNMP záznamov: ${data.snmp_data?.length || 0}`);
            }
            
            if (data.status === 'success') {
                if (data.ping_data && data.ping_data.length > 0) {
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`🏓 Spracovávam ping dáta: ${data.ping_data.length} bodov`);
                    }
                    updatePingChart({ device_id: deviceId, history: data.ping_data });
                } else {
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`❌ Žiadne ping dáta - čistím graf`);
                    }
                    // Clear ping chart if no data
                    if (charts.ping) {
                        charts.ping.data.datasets[0].data = [];
                        charts.ping.update('none');
                    }
                }
                
                if (data.snmp_data && data.snmp_data.length > 0) {
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`📈 Spracovávam SNMP dáta: ${data.snmp_data.length} bodov`);
                    }
                    updateSNMPCharts({ history: data.snmp_data });
                } else {
                    // Clear SNMP charts if no data
                    if (charts.cpu) {
                        charts.cpu.data.datasets[0].data = [];
                        charts.cpu.update('none');
                    }
                    if (charts.temperature) {
                        charts.temperature.data.datasets[0].data = [];
                        charts.temperature.update('none');
                    }
                    if (charts.memory) {
                        charts.memory.data.datasets[0].data = [];
                        charts.memory.data.datasets[1].data = [];
                        charts.memory.update('none');
                    }
                }
                
                // Load availability data (always load, independent of time range) - REMOVED
                // await updateAvailabilityChart(deviceId);
                
                // Ak sme používali optimized range, načítaj postupne plné dáta na pozadí
                // VÝNIMKA: Nerobí background loading počas single chart zoom-out alebo zoom-out expansion
                if (optimizedRange !== timeRange && !window._singleChartZoomOut && !window._isZoomOutExpansion) {
                    setTimeout(async () => {
                        try {
                            // Map frontend range names to backend range names
                            const apiTimeRange = timeRange === '30m' ? 'recent' : timeRange;
                            const fullApiUrl = `api/monitoring/history/${deviceId}?range=${apiTimeRange}`;
                            const fullResponse = await fetch(`/${fullApiUrl}`);
                            if (fullResponse.ok) {
                                const fullData = await fullResponse.json();
                                if (fullData.status === 'success') {
                                    // Aktualizuj grafy s plnými dátami
                                    if (fullData.ping_data && fullData.ping_data.length > 0) {
                                        updatePingChart({ device_id: deviceId, history: fullData.ping_data });
                                    }
                                    if (fullData.snmp_data && fullData.snmp_data.length > 0) {
                                        updateSNMPCharts({ history: fullData.snmp_data });
                                    }
                                    
                                    // Apply full time range horizon after background loading
                                    if (typeof window.applyFullTimeRangeToAllCharts === 'function') {
                                        setTimeout(() => {
                                            window.applyFullTimeRangeToAllCharts();
                                        }, 100);
                                    }
                                    
                                }
                            }
                        } catch (bgError) {
                            console.error('Background loading error:', bgError);
                        }
                    }, 1000); // Načítaj po 1 sekunde
                }
            } else {
                console.error('API returned error:', data.message);
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`❌ API chyba: ${data.message || 'Neznáma chyba'}`);
                }
                showError('Chyba pri načítaní dát: ' + (data.message || 'Neznáma chyba'));
            }
            
            // Apply initial Y-axis optimization after all data is loaded
            setTimeout(() => {
                optimizeAllChartsYAxes();
            }, 200);
            
            
            if (typeof addDebugLog === 'function') {
                addDebugLog(`✅ Načítanie historických dát dokončené pre ${deviceId}`);
            }
            
        } catch (error) {
            if (error.name === 'AbortError') {
                console.error('Request timeout - loading took too long');
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`⏱️ Timeout - načítavanie trvalo príliš dlho`);
                }
                showError('Načítavanie trvá príliš dlho. Skúste kratší časový rozsah.');
            } else {
                console.error('Error loading historical data:', error);
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`💥 Chyba pri načítaní historických dát: ${error.message}`);
                }
                showError('Chyba pri načítaní historických dát: ' + error.message);
            }
        } finally {
            isLoadingData = false;
            if (typeof addDebugLog === 'function') {
                addDebugLog(`🏁 loadHistoricalData ukončené pre ${deviceId}`);
            }
        }
    };
    
    // Get current ping status (from database, no new ping)
    const getCurrentPingStatus = async (deviceId) => {
        try {
            // Získa posledný ping stav z databázy bez spustenia nového ping-u
            const pingHistory = await api.get(`monitoring/ping/${deviceId}`);
            if (pingHistory && pingHistory.length > 0) {
                const latestPing = pingHistory[pingHistory.length - 1];
                updatePingStatus({
                    status: latestPing.status,
                    avg_latency: latestPing.avg_latency,
                    packet_loss: latestPing.packet_loss,
                    timestamp: latestPing.timestamp
                });
            }
        } catch (error) {
            console.error('Chyba pri načítaní ping stavu:', error);
        }
    };
    
    // Manual ping - force new ping
    const triggerManualPing = async (deviceId) => {
        try {
            const pingResult = await api.post(`monitoring/ping/manual/${deviceId}`, {});
            if (pingResult) {
                updatePingStatus(pingResult);
            }
        } catch (error) {
            console.error('Chyba pri manuálnom ping:', error);
        }
    };
    
    // Pause/Resume monitoring functionality
    const updatePauseResumeButton = (isPaused) => {
        if (!pauseResumeBtn || !pauseResumeIcon || !pauseResumeText) return;
        
        if (isPaused) {
            pauseResumeBtn.className = 'btn bg-green-600 hover:bg-green-700 text-white px-3 py-2 rounded-lg flex items-center gap-2';
            pauseResumeIcon.className = 'fas fa-play';
            pauseResumeText.textContent = 'Spustiť';
            pauseResumeBtn.title = 'Spustiť monitoring zariadenia';
        } else {
            pauseResumeBtn.className = 'btn bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-2 rounded-lg flex items-center gap-2';
            pauseResumeIcon.className = 'fas fa-pause';
            pauseResumeText.textContent = 'Pozastaviť';
            pauseResumeBtn.title = 'Pozastaviť monitoring zariadenia';
        }
        
        pauseResumeBtn.classList.remove('hidden');
    };
    
    const toggleDeviceMonitoring = async (deviceId) => {
        if (!deviceId) return;
        
        try {
            // Disable button during request
            pauseResumeBtn.disabled = true;
            pauseResumeBtn.classList.add('opacity-50');
            
            const result = await api.post(`monitoring/device/${deviceId}/pause`, {});
            
            if (result.status === 'success') {
                const isPaused = result.monitoring_paused;
                
                // Update button appearance
                updatePauseResumeButton(isPaused);
                
                // Update device status in selector
                updateDeviceStatusInSelector(deviceId, deviceStatusCache.get(deviceId) || 'unknown', isPaused);
                
                // Show success message
                const action = isPaused ? 'pozastavené' : 'spustené';
                
                // If monitoring was resumed, reload data and trigger immediate ping
                if (!isPaused) {
                    await loadHistoricalData(deviceId);
                    // Trigger immediate ping to update status
                    try {
                        await api.post(`monitoring/ping/manual/${deviceId}`, {});
                    } catch (pingError) {
                        console.warn('Manual ping after resume failed:', pingError);
                    }
                }
                
            } else {
                throw new Error(result.message || 'Neznáma chyba');
            }
        } catch (error) {
            console.error('Chyba pri zmene stavu monitoringu:', error);
            showError('Chyba pri zmene stavu monitoringu: ' + error.message);
        } finally {
            // Re-enable button
            pauseResumeBtn.disabled = false;
            pauseResumeBtn.classList.remove('opacity-50');
        }
    };

    // Device selection handler
    const selectDevice = async (deviceId) => {
        
        // Stop Y-axis optimization for previous device
        stopYAxisOptimization();
        
        currentDeviceId = deviceId ? parseInt(deviceId) : null;
        window.currentDeviceId = currentDeviceId; // Export for zoom functionality
        
        if (!currentDeviceId) {
            hideDeviceInfo();
            hideTimeRangeSelector();
            saveState();
            return;
        }
        
        showTimeRangeSelector();
        showLoadingIndicator();
        
        // Save current state
        saveState();
        
        try {
            // Load device info and ping status
            const devices = await api.get('devices');
            const device = devices.find(d => d.id === currentDeviceId);
            
            if (device) {
                displayDeviceInfo(device);
                updatePauseResumeButton(device.monitoring_paused);
                showDeviceInfo();
                await Promise.all([
                    loadHistoricalData(currentDeviceId),
                    getCurrentPingStatus(currentDeviceId)
                ]);
                showCharts();
                initializePingUpdates();
                
                // Start Y-axis optimization for real-time updates (only if page is visible)
                if (document.visibilityState === 'visible') {
                    startYAxisOptimization();
                } else {
                }
            }
        } catch (error) {
            console.error('Error selecting device:', error);
        } finally {
            hideLoadingIndicator();
        }
    };
    
    // Show/hide time range selector with animation
    const showTimeRangeSelector = () => {
        timeRangeContainer.classList.remove('hidden');
        // Small delay to ensure the element is rendered before animation
        setTimeout(() => {
            timeRangeContainer.classList.add('show');
        }, 10);
    };
    
    const hideTimeRangeSelector = () => {
        timeRangeContainer.classList.remove('show');
        setTimeout(() => {
            timeRangeContainer.classList.add('hidden');
        }, 300);
    };
    
    // Display device info - optimized version
    const displayDeviceInfo = (device) => {
        // Use cached DOM elements for better performance
        const deviceName = domCache.deviceName || document.getElementById('deviceName');
        const deviceIp = domCache.deviceIp || document.getElementById('deviceIp');
        const deviceModel = domCache.deviceModel || document.getElementById('deviceModel');
        
        requestAnimationFrame(() => {
            if (deviceName) deviceName.textContent = device.name;
            if (deviceIp) deviceIp.textContent = device.ip; // IP sa zobrazí len na mobile cez CSS
            
            // Display model and RouterOS version from last_snmp_data if available
            if (deviceModel) {
                let modelText = '';
                if (device.last_snmp_data) {
                    try {
                        const snmpData = typeof device.last_snmp_data === 'string' 
                            ? JSON.parse(device.last_snmp_data) 
                            : device.last_snmp_data;
                        
                        if (snmpData.board_name && snmpData.board_name !== 'N/A') {
                            modelText = snmpData.board_name;
                        }
                        if (snmpData.version && snmpData.version !== 'N/A') {
                            if (modelText) {
                                modelText += ` - RouterOS ${snmpData.version}`;
                            } else {
                                modelText = `RouterOS ${snmpData.version}`;
                            }
                        }
                    } catch (e) {
                    }
                }
                deviceModel.textContent = modelText || 'N/A';
            }
        });
    };
    
    // Start ping monitoring
    const startPingMonitoring = (deviceId) => {
        // Clear existing interval
        if (pingUpdateInterval) {
            clearInterval(pingUpdateInterval);
        }
        
        // Nebudeme spúšťať vlastný interval - spoliehame sa na backend ping monitoring
        // Backend už pinguje zariadenia podľa nastavených intervalov
    };
    
    // Show/hide sections
    const showNoDeviceSelected = () => {
        deviceInfoPanel.classList.add('hidden');
        chartsContainer.classList.add('hidden');
        noDeviceSelected.classList.remove('hidden');
        loadingIndicator.classList.add('hidden');
    };
    
    const showDeviceInfo = () => {
        noDeviceSelected.classList.add('hidden');
        loadingIndicator.classList.add('hidden');
        deviceInfoPanel.classList.remove('hidden');
        chartsContainer.classList.remove('hidden');
    };
    
    const hideDeviceInfo = () => {
        deviceInfoPanel.classList.add('hidden');
        chartsContainer.classList.add('hidden');
        if (pauseResumeBtn) {
            pauseResumeBtn.classList.add('hidden');
        }
        showNoDeviceSelected();
    };
    
    const showCharts = () => {
        chartsContainer.classList.remove('hidden');
    };
    
    const showLoadingIndicator = () => {
        loadingIndicator.classList.remove('hidden');
        noDeviceSelected.classList.add('hidden');
        deviceInfoPanel.classList.add('hidden');
        chartsContainer.classList.add('hidden');
    };
    
    const hideLoadingIndicator = () => {
        loadingIndicator.classList.add('hidden');
    };
    
    // Show error message to user
    const showError = (message) => {
        console.error('Showing error to user:', message);
        // Create temporary error notification
        const errorDiv = document.createElement('div');
        errorDiv.className = 'fixed top-4 right-4 bg-red-600 text-white px-4 py-2 rounded-lg shadow-lg z-50 max-w-md';
        errorDiv.innerHTML = `
            <div class="flex items-center">
                <i class="fas fa-exclamation-triangle mr-2"></i>
                <span class="text-sm">${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-white hover:text-gray-200">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        document.body.appendChild(errorDiv);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (errorDiv.parentElement) {
                errorDiv.remove();
            }
        }, 5000);
    };
    
    const initializePingUpdates = () => {
        // Initialize real-time ping updates for the selected device
        // This will be handled by WebSocket events
    };
    
    const showLoading = (show) => {
        if (show) {
            loadingIndicator.classList.remove('hidden');
            deviceInfoPanel.classList.add('hidden');
            chartsContainer.classList.add('hidden');
            noDeviceSelected.classList.add('hidden');
        } else {
            loadingIndicator.classList.add('hidden');
            if (currentDeviceId) {
                showDeviceInfo();
            } else {
                showNoDeviceSelected();
            }
        }
    };
    
    // Event listeners
    deviceSelector.addEventListener('change', (e) => {
        selectDevice(e.target.value);
    });
    
        // Time range buttons event listeners
        document.addEventListener('click', async (e) => {
            if (e.target.classList.contains('time-range-btn')) {
                if (isLoadingData) return; // Prevent clicks during loading
                
                // Add debug log for global time range button click
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`🌐 Globálne časové tlačidlo kliknuté: ${e.target.dataset.range}`);
                }
                
                // Check if global time range changes are blocked during single chart expansion
                if (window._blockGlobalTimeRangeChanges) {
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`❌ Globálna zmena času blokovaná - single chart expansion aktívny`);
                    }
                    return;
                }
                
                const newTimeRange = e.target.dataset.range;
                
                // Get current time range for animation direction
                const currentTimeRange = getSelectedTimeRange();
                
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`🔄 Globálna zmena času: ${currentTimeRange} → ${newTimeRange}`);
                }
                
                // Emergency cleanup of any stuck selection boxes
                if (typeof cleanupAllSelections === 'function') {
                    cleanupAllSelections();
                }
                
                // Determine animation direction and apply smooth transition
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`🎬 Spúšťam animáciu prechodu času: ${currentTimeRange} → ${newTimeRange}`);
                }
                
                try {
                    await applyTimeRangeTransition(currentTimeRange, newTimeRange);
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`🎭 Animácia prechodu dokončená: ${currentTimeRange} → ${newTimeRange}`);
                    }
                } catch (error) {
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`❌ Chyba pri animácii prechodu: ${error.message}`);
                    }
                }
                
                // Set active time range
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`✅ Nastavujem aktívny časový rozsah: ${newTimeRange}`);
                    addDebugLog(`🔍 Pre-setActiveTimeRange: _blockGlobalTimeRangeChanges = ${window._blockGlobalTimeRangeChanges || false}`);
                }
                setActiveTimeRange(newTimeRange);
                
                // (Odstránené loading spinner na tlačidle – vizuálne rušivé)
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`⏳ (Preskočené) loading state na tlačidlo: ${newTimeRange}`);
                }
                
                if (typeof addDebugLog === 'function') {
                    addDebugLog(`🔍 Kontrola currentDeviceId: ${currentDeviceId || 'undefined'}`);
                }
                
                if (currentDeviceId) {
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`📊 Načítavam historické dáta pre device ${currentDeviceId}, rozsah: ${newTimeRange}`);
                    }
                    try {
                        await loadHistoricalData(currentDeviceId, false); // No loading animation for time range changes
                        if (typeof addDebugLog === 'function') {
                            addDebugLog(`✅ Historické dáta úspešne načítané pre ${newTimeRange}`);
                        }
                    } catch (error) {
                        if (typeof addDebugLog === 'function') {
                            addDebugLog(`❌ Chyba pri načítaní historických dát: ${error.message}`);
                        }
                    } finally {
                        // Žiadny loading state na odstránenie
                    }
                } else {
                    if (typeof addDebugLog === 'function') {
                        addDebugLog(`⚠️ Žiadny currentDeviceId - loading state nebol použitý`);
                    }
                    // nič
                }
            }
        });    refreshBtn.addEventListener('click', async (e) => {
        e.preventDefault(); // Zabráni default správaniu
        
        if (!currentDeviceId) return;
        
        try {
            // Emergency cleanup of any stuck selection boxes
            if (typeof cleanupAllSelections === 'function') {
                cleanupAllSelections();
            }
            
            // Reset zoom on all charts before refresh (same as time range buttons)
            if (typeof resetAllChartsZoom === 'function') {
                resetAllChartsZoom();
                
                // Wait longer for zoom reset to complete and charts to update
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            
            // Tichá aktualizácia dát na pozadí - tlačidlo zostane normálne
            await Promise.all([
                loadHistoricalData(currentDeviceId),
                getCurrentPingStatus(currentDeviceId)  // Len číta stav z databázy, nespúšťa nový ping
            ]);
            
            // Force final chart update after data load
            setTimeout(() => {
                Object.values(charts).forEach(chart => {
                    if (chart) {
                        chart.update();
                    }
                });
            }, 50);
            
        } catch (error) {
            console.error('Chyba pri obnovovaní:', error);
            // V prípade chyby stále zobrazíme notifikáciu
            showError('Chyba pri obnovovaní dát: ' + error.message);
        }
    });
    
    // Pause/Resume button event listener
    pauseResumeBtn.addEventListener('click', async () => {
        if (!currentDeviceId) return;
        await toggleDeviceMonitoring(currentDeviceId);
    });
    
    // Device settings modal handlers
    deviceSettingsBtn.addEventListener('click', async () => {
        if (!currentDeviceId) return;
        
        try {
            const settings = await api.get(`monitoring/device/${currentDeviceId}/settings`);
            
            // Populate modal
            document.getElementById('settingsDeviceInfo').textContent = 
                `${settings.device.name} (${settings.device.ip})`;
            document.getElementById('pingInterval').value = settings.device.ping_interval_seconds;
            document.getElementById('snmpInterval').value = settings.device.snmp_interval_minutes;
            
            // Show modal
            deviceSettingsModal.classList.remove('hidden');
        } catch (error) {
            console.error('Chyba pri načítaní nastavení:', error);
            alert('Chyba pri načítaní nastavení zariadenia');
        }
    });
    
    const closeModal = () => {
        deviceSettingsModal.classList.add('hidden');
    };
    
    closeSettingsModal.addEventListener('click', closeModal);
    cancelSettings.addEventListener('click', closeModal);
    
    deviceSettingsModal.addEventListener('click', (e) => {
        if (e.target === deviceSettingsModal) {
            closeModal();
        }
    });
    
    deviceSettingsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        if (!currentDeviceId) return;
        
        const formData = new FormData(e.target);
        const data = {
            ping_interval_seconds: parseInt(formData.get('ping_interval_seconds')) || 0,
            snmp_interval_minutes: parseInt(formData.get('snmp_interval_minutes')) || 0
        };
        
        try {
            const result = await api.post(`monitoring/device/${currentDeviceId}/settings`, data);
            
            if (result.status === 'success') {
                closeModal();
                // Odstránené alert - len zatvorí okno
            } else {
                console.error('Chyba pri ukladaní:', result.message);
                // Len v prípade chyby môžeme zobraziť alert
                alert(result.message || 'Chyba pri ukladaní nastavení');
            }
        } catch (error) {
            console.error('Chyba pri ukladaní nastavení:', error);
            alert('Chyba pri ukladaní nastavení');
        }
    });
    
    // Initialize
    const initialize = async () => {
        
        // Cache DOM elements for better performance
        cacheDOM();
        
        await loadDevices();
        
        initializeCharts();
        
        initializeSocket();
        
        // Restore saved state
        const savedState = loadState();
        
        if (savedState) {
            
            if (savedState.timeRange) {
                setActiveTimeRange(savedState.timeRange);
            }
            
            if (savedState.deviceId) {
                // Set device selector value
                if (window.customDeviceSelector) {
                    window.customDeviceSelector.setValue(savedState.deviceId);
                } else {
                    deviceSelector.value = savedState.deviceId;
                }
                // Trigger device selection
                await selectDevice(savedState.deviceId);
            } else {
                showNoDeviceSelected();
            }
        } else {
            // Set default time range formatting
            setActiveTimeRange(currentTimeRange);
            
            // Auto-select first device if available
            const firstOption = window.customDeviceSelector ? 
                document.querySelector('#deviceSelectorDropdown .custom-select-option[data-value]:not([data-value=""])') :
                deviceSelector.querySelector('option[value]:not([value=""])');
            if (firstOption) {
                const firstDeviceId = window.customDeviceSelector ? 
                    firstOption.getAttribute('data-value') : 
                    firstOption.value;
                if (window.customDeviceSelector) {
                    window.customDeviceSelector.setValue(firstDeviceId);
                } else {
                    deviceSelector.value = firstDeviceId;
                }
                await selectDevice(firstDeviceId);
            } else {
                showNoDeviceSelected();
            }
        }
        
    };
    
    // Page Visibility API - pause optimization when page is not visible
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            stopYAxisOptimization();
        } else if (document.visibilityState === 'visible' && currentDeviceId) {
            // Small delay to ensure everything is ready
            setTimeout(() => {
                startYAxisOptimization();
            }, 1000);
        }
    });

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        stopYAxisOptimization();
        if (pingUpdateInterval) {
            clearInterval(pingUpdateInterval);
        }
        if (socket) {
            socket.disconnect();
        }
    });
    
    // Start the application
    initialize();
    
    // Export global variables for zoom functionality
    window.currentDeviceId = currentDeviceId;
    window.currentTimeRange = currentTimeRange;
    window.loadHistoricalData = loadHistoricalData;
    window.updateChartTimeFormats = updateChartTimeFormats;
    window.setActiveTimeRange = setActiveTimeRange;
});
