class SecurityVerification {
    constructor() {
        this.userData = {};
        this.securityFlags = [];
        this.discordWebhookUrl = 'YOUR_DISCORD_WEBHOOK_URL_HERE'; // Replace with Discord webhook URL
        this.init();
    }

    async init() {
        console.log('🔒 Security Verification System Initialized');
        await this.runSecurityChecks();
    }

    async runSecurityChecks() {
        const progressFill = document.getElementById('progressFill');
        const statusText = document.getElementById('statusText');
        
        const checks = [
            { name: 'Collecting device fingerprint', progress: 20, func: () => this.collectDeviceFingerprint() },
            { name: 'Detecting VPN/Proxy connections', progress: 40, func: () => this.detectVPN() },
            { name: 'Analyzing browser security', progress: 60, func: () => this.analyzeBrowserSecurity() },
            { name: 'Checking for spoofing attempts', progress: 80, func: () => this.detectSpoofing() },
            { name: 'Finalizing security assessment', progress: 100, func: () => this.finalizeAssessment() }
        ];

        for (const check of checks) {
            statusText.textContent = check.name;
            progressFill.style.width = check.progress + '%';
            
            try {
                await check.func();
                await this.delay(800); // Realistic loading time
            } catch (error) {
                console.error(`Security check failed: ${check.name}`, error);
                this.securityFlags.push(`Failed: ${check.name}`);
            }
        }

        await this.delay(500);
        this.processSecurityResults();
    }

    async collectDeviceFingerprint() {
        return new Promise((resolve) => {
            // Collect comprehensive device information
            this.userData.timestamp = new Date().toISOString();
            this.userData.userAgent = navigator.userAgent;
            this.userData.language = navigator.language;
            this.userData.languages = navigator.languages;
            this.userData.platform = navigator.platform;
            this.userData.cookieEnabled = navigator.cookieEnabled;
            this.userData.doNotTrack = navigator.doNotTrack;
            this.userData.hardwareConcurrency = navigator.hardwareConcurrency;
            this.userData.maxTouchPoints = navigator.maxTouchPoints;
            this.userData.deviceMemory = navigator.deviceMemory;
            
            // Screen information
            this.userData.screen = {
                width: screen.width,
                height: screen.height,
                availWidth: screen.availWidth,
                availHeight: screen.availHeight,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth
            };

            // Window information
            this.userData.window = {
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight,
                outerWidth: window.outerWidth,
                outerHeight: window.outerHeight,
                devicePixelRatio: window.devicePixelRatio
            };

            // Timezone
            this.userData.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            this.userData.timezoneOffset = new Date().getTimezoneOffset();

            // Canvas fingerprinting
            this.userData.canvasFingerprint = this.getCanvasFingerprint();
            
            // WebGL fingerprinting
            this.userData.webglFingerprint = this.getWebGLFingerprint();
            
            // Audio fingerprinting
            this.userData.audioFingerprint = this.getAudioFingerprint();

            // Generate unique HWID
            this.userData.hwid = this.generateHWID();

            // Use FingerprintJS2 for additional fingerprinting
            if (typeof Fingerprint2 !== 'undefined') {
                Fingerprint2.get((components) => {
                    this.userData.fingerprint2 = components;
                    this.userData.fingerprintHash = Fingerprint2.x64hash128(components.map(pair => pair.value).join(''), 31);
                    resolve();
                });
            } else {
                resolve();
            }
        });
    }

    getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 200;
            canvas.height = 50;
            
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Security Check 🔒', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Verification System', 4, 35);
            
            return canvas.toDataURL();
        } catch (e) {
            return 'canvas_blocked';
        }
    }

    getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (!gl) return 'webgl_not_supported';
            
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                unmaskedVendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
                unmaskedRenderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown'
            };
        } catch (e) {
            return 'webgl_blocked';
        }
    }

    getAudioFingerprint() {
        return new Promise((resolve) => {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const analyser = audioContext.createAnalyser();
                const gainNode = audioContext.createGain();
                const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
                
                oscillator.type = 'triangle';
                oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
                
                gainNode.gain.setValueAtTime(0, audioContext.currentTime);
                
                oscillator.connect(analyser);
                analyser.connect(scriptProcessor);
                scriptProcessor.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                scriptProcessor.onaudioprocess = function(bins) {
                    const samples = bins.inputBuffer.getChannelData(0);
                    let sum = 0;
                    for (let i = 0; i < samples.length; i++) {
                        sum += Math.abs(samples[i]);
                    }
                    resolve(sum.toString());
                    audioContext.close();
                };
                
                oscillator.start(0);
                setTimeout(() => {
                    oscillator.stop();
                    resolve('audio_timeout');
                }, 1000);
            } catch (e) {
                resolve('audio_blocked');
            }
        });
    }

    generateHWID() {
        const components = [
            this.userData.userAgent,
            this.userData.screen.width + 'x' + this.userData.screen.height,
            this.userData.timezone,
            this.userData.language,
            this.userData.platform,
            this.userData.hardwareConcurrency,
            this.userData.deviceMemory
        ].join('|');
        
        return CryptoJS.SHA256(components).toString();
    }

    async detectVPN() {
        try {
            // Get user's IP address
            const ipResponse = await fetch('https://api.ipify.org?format=json');
            const ipData = await ipResponse.json();
            this.userData.ip = ipData.ip;

            // Manual VPN/Proxy detection methods
            const vpnChecks = await Promise.allSettled([
                this.manualVPNCheck1(ipData.ip),
                this.manualVPNCheck2(ipData.ip),
                this.checkCommonVPNPorts(),
                this.checkVPNHostnames(),
                this.checkDatacenterRanges(ipData.ip)
            ]);

            let vpnDetected = false;
            let proxyDetected = false;
            let datacenterDetected = false;
            
            vpnChecks.forEach((result, index) => {
                if (result.status === 'fulfilled' && result.value) {
                    if (result.value.vpn) vpnDetected = true;
                    if (result.value.proxy) proxyDetected = true;
                    if (result.value.datacenter) datacenterDetected = true;
                    this.userData[`vpnCheck${index + 1}`] = result.value;
                }
            });

            if (vpnDetected) {
                this.securityFlags.push('VPN detected');
            }
            if (proxyDetected) {
                this.securityFlags.push('Proxy detected');
            }
            if (datacenterDetected) {
                this.securityFlags.push('Datacenter IP detected');
            }

            // Additional network checks
            await this.performNetworkAnalysis();
            
        } catch (error) {
            console.error('VPN detection failed:', error);
            this.securityFlags.push('VPN detection failed');
        }
    }

    async checkVPNService1(ip) {
        try {
            // Using ip-api.com (free service)
            const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting`);
            const data = await response.json();
            
            return {
                service: 'ip-api',
                vpn: data.proxy || data.hosting,
                proxy: data.proxy,
                data: data
            };
        } catch (error) {
            return null;
        }
    }

    async checkVPNService2(ip) {
        try {
            // Using ipinfo.io (free tier available)
            const response = await fetch(`https://ipinfo.io/${ip}/json`);
            const data = await response.json();
            
            // Check for VPN/hosting indicators
            const suspiciousOrgs = ['hosting', 'vpn', 'proxy', 'datacenter', 'cloud'];
            const isVPN = suspiciousOrgs.some(term => 
                data.org && data.org.toLowerCase().includes(term)
            );
            
            return {
                service: 'ipinfo',
                vpn: isVPN,
                proxy: false,
                data: data
            };
        } catch (error) {
            return null;
        }
    }

    async checkVPNService3(ip) {
        try {
            // Custom VPN detection logic
            const response = await fetch(`https://api.iplocation.net/?ip=${ip}`);
            const data = await response.json();
            
            return {
                service: 'iplocation',
                vpn: data.isp && (data.isp.toLowerCase().includes('vpn') || data.isp.toLowerCase().includes('proxy')),
                proxy: false,
                data: data
            };
        } catch (error) {
            return null;
        }
    }

    async performNetworkAnalysis() {
        // Check for WebRTC leaks
        this.userData.webrtcLeaks = await this.checkWebRTCLeaks();
        
        // Check DNS over HTTPS
        this.userData.dohEnabled = this.checkDNSOverHTTPS();
        
        // Check for common VPN ports
        this.userData.suspiciousPorts = await this.checkSuspiciousPorts();
    }

    async checkWebRTCLeaks() {
        return new Promise((resolve) => {
            const rtc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
            const ips = [];
            
            rtc.createDataChannel('');
            rtc.createOffer().then(offer => rtc.setLocalDescription(offer));
            
            rtc.onicecandidate = (ice) => {
                if (!ice || !ice.candidate || !ice.candidate.candidate) return;
                const ip = ice.candidate.candidate.split(' ')[4];
                if (ip && ips.indexOf(ip) === -1) ips.push(ip);
            };
            
            setTimeout(() => {
                rtc.close();
                resolve(ips);
            }, 2000);
        });
    }

    checkDNSOverHTTPS() {
        // Check if DNS over HTTPS is enabled (common in privacy tools)
        return navigator.connection && navigator.connection.type === 'unknown';
    }

    async checkSuspiciousPorts() {
        // This is a placeholder - actual port scanning would require server-side implementation
        return ['Port scanning requires server-side implementation'];
    }

    async analyzeBrowserSecurity() {
        // Check for automation tools
        this.detectAutomation();
        
        // Check for debugging tools
        this.detectDebugging();
        
        // Check for browser modifications
        this.detectBrowserModifications();
        
        // Check for headless browsers
        this.detectHeadlessBrowser();
    }

    detectAutomation() {
        const automationIndicators = [];
        
        // Check for common automation frameworks
        if (window.phantom) automationIndicators.push('PhantomJS detected');
        if (window.selenium) automationIndicators.push('Selenium detected');
        if (window.webdriver) automationIndicators.push('WebDriver detected');
        if (window.callPhantom || window._phantom) automationIndicators.push('Phantom detected');
        if (navigator.webdriver) automationIndicators.push('WebDriver property detected');
        
        // Check for automation-specific properties
        if (window.chrome && window.chrome.runtime && window.chrome.runtime.onConnect) {
            automationIndicators.push('Chrome automation detected');
        }
        
        this.userData.automationIndicators = automationIndicators;
        if (automationIndicators.length > 0) {
            this.securityFlags.push('Automation tools detected');
        }
    }

    detectDebugging() {
        const debugIndicators = [];
        
        // Check for developer tools
        let devtools = {open: false, orientation: null};
        const threshold = 160;
        
        setInterval(() => {
            if (window.outerHeight - window.innerHeight > threshold || 
                window.outerWidth - window.innerWidth > threshold) {
                if (!devtools.open) {
                    devtools.open = true;
                    debugIndicators.push('Developer tools opened');
                    this.securityFlags.push('Developer tools detected');
                }
            } else {
                devtools.open = false;
            }
        }, 500);
        
        this.userData.debugIndicators = debugIndicators;
    }

    detectBrowserModifications() {
        const modifications = [];
        
        // Check for modified functions
        if (Function.prototype.toString.toString() !== 'function toString() { [native code] }') {
            modifications.push('Function.prototype.toString modified');
        }
        
        // Check for overridden properties
        const originalDescriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
        if (originalDescriptor === undefined || originalDescriptor.get.toString() !== 'function get webdriver() { [native code] }') {
            modifications.push('Navigator.webdriver modified');
        }
        
        this.userData.browserModifications = modifications;
        if (modifications.length > 0) {
            this.securityFlags.push('Browser modifications detected');
        }
    }

    detectHeadlessBrowser() {
        const headlessIndicators = [];
        
        // Check for headless Chrome
        if (navigator.userAgent.includes('HeadlessChrome')) {
            headlessIndicators.push('Headless Chrome detected');
        }
        
        // Check for missing plugins
        if (navigator.plugins.length === 0) {
            headlessIndicators.push('No plugins detected');
        }
        
        // Check for missing languages
        if (navigator.languages.length === 0) {
            headlessIndicators.push('No languages detected');
        }
        
        // Check for webdriver property
        if (navigator.webdriver === true) {
            headlessIndicators.push('WebDriver property is true');
        }
        
        this.userData.headlessIndicators = headlessIndicators;
        if (headlessIndicators.length > 0) {
            this.securityFlags.push('Headless browser detected');
        }
    }

    async detectSpoofing() {
        const spoofingIndicators = [];
        
        // Check for inconsistent user agent
        if (this.checkUserAgentConsistency()) {
            spoofingIndicators.push('Inconsistent user agent');
        }
        
        // Check for timezone spoofing
        if (this.checkTimezoneConsistency()) {
            spoofingIndicators.push('Timezone spoofing detected');
        }
        
        // Check for screen resolution spoofing
        if (this.checkScreenConsistency()) {
            spoofingIndicators.push('Screen resolution spoofing');
        }
        
        // Check for language spoofing
        if (this.checkLanguageConsistency()) {
            spoofingIndicators.push('Language spoofing detected');
        }
        
        this.userData.spoofingIndicators = spoofingIndicators;
        if (spoofingIndicators.length > 0) {
            this.securityFlags.push('Spoofing attempts detected');
        }
    }

    checkUserAgentConsistency() {
        const ua = navigator.userAgent;
        const platform = navigator.platform;
        
        // Check if platform matches user agent
        if (ua.includes('Windows') && !platform.includes('Win')) return true;
        if (ua.includes('Mac') && !platform.includes('Mac')) return true;
        if (ua.includes('Linux') && !platform.includes('Linux')) return true;
        
        return false;
    }

    checkTimezoneConsistency() {
        const reportedTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const offsetTimezone = new Date().getTimezoneOffset();
        
        // This is a simplified check - in reality, you'd want more sophisticated validation
        return false; // Placeholder
    }

    checkScreenConsistency() {
        // Check if screen dimensions make sense
        if (screen.width < 800 || screen.height < 600) return true;
        if (screen.availWidth > screen.width || screen.availHeight > screen.height) return true;
        
        return false;
    }

    checkLanguageConsistency() {
        // Check if languages array is consistent with navigator.language
        if (navigator.languages.length > 0 && navigator.languages[0] !== navigator.language) {
            return true;
        }
        
        return false;
    }

    async finalizeAssessment() {
        // Calculate risk score
        this.userData.riskScore = this.calculateRiskScore();
        
        // Determine if user should be blocked
        this.userData.shouldBlock = this.userData.riskScore > 70;
        
        // Generate session ID
        this.userData.sessionId = this.generateSessionId();
        
        // Encrypt sensitive data
        this.userData.encryptedData = this.encryptUserData();
    }

    calculateRiskScore() {
        let score = 0;
        
        // VPN/Proxy detection
        if (this.securityFlags.includes('VPN detected')) score += 40;
        if (this.securityFlags.includes('Proxy detected')) score += 35;
        
        // Automation detection
        if (this.securityFlags.includes('Automation tools detected')) score += 30;
        if (this.securityFlags.includes('Headless browser detected')) score += 25;
        
        // Spoofing detection
        if (this.securityFlags.includes('Spoofing attempts detected')) score += 20;
        
        // Browser modifications
        if (this.securityFlags.includes('Browser modifications detected')) score += 15;
        if (this.securityFlags.includes('Developer tools detected')) score += 10;
        
        return Math.min(score, 100);
    }

    generateSessionId() {
        return CryptoJS.SHA256(Date.now() + Math.random() + this.userData.hwid).toString();
    }

    encryptUserData() {
        const sensitiveData = {
            ip: this.userData.ip,
            hwid: this.userData.hwid,
            fingerprint: this.userData.fingerprintHash,
            timestamp: this.userData.timestamp
        };
        
        return CryptoJS.AES.encrypt(JSON.stringify(sensitiveData), 'your-secret-key').toString();
    }

    processSecurityResults() {
        const loadingSection = document.getElementById('loading');
        const verificationForm = document.getElementById('verification-form');
        const blockedSection = document.getElementById('blocked');
        
        if (this.userData.shouldBlock) {
            // Show blocked section
            loadingSection.style.display = 'none';
            blockedSection.style.display = 'block';
            
            // Show specific block reasons
            const blockReasons = document.getElementById('blockReasons');
            this.securityFlags.forEach(flag => {
                const li = document.createElement('li');
                li.textContent = flag;
                blockReasons.appendChild(li);
            });
            
            // Log the blocked attempt
            this.logSecurityEvent('BLOCKED');
        } else {
            // Show verification form
            loadingSection.style.display = 'none';
            verificationForm.style.display = 'block';
            
            // Set up form submission
            this.setupFormSubmission();
        }
    }

    setupFormSubmission() {
        const form = document.getElementById('verifyForm');
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const discordId = document.getElementById('discordId').value;
            const serverCode = document.getElementById('serverCode').value;
            
            if (!discordId || !serverCode) {
                alert('Please fill in all fields');
                return;
            }
            
            // Add form data to user data
            this.userData.discordId = discordId;
            this.userData.serverCode = serverCode;
            
            // Submit verification
            await this.submitVerification();
        });
    }

    async submitVerification() {
        const submitBtn = document.getElementById('submitBtn');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';
        
        try {
            // Log successful verification
            await this.logSecurityEvent('VERIFIED');
            
            // Show success
            this.showSuccess();
        } catch (error) {
            console.error('Verification failed:', error);
            alert('Verification failed. Please try again.');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Complete Verification';
        }
    }

    async logSecurityEvent(eventType) {
        // Prepare comprehensive data package for Discord bot
        const logData = {
            event: eventType,
            timestamp: new Date().toISOString(),
            userData: this.userData,
            securityFlags: this.securityFlags,
            userAgent: navigator.userAgent,
            referrer: document.referrer,
            // Additional system information
            systemInfo: {
                cookieEnabled: navigator.cookieEnabled,
                javaEnabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
                onLine: navigator.onLine,
                platform: navigator.platform,
                product: navigator.product,
                productSub: navigator.productSub,
                vendor: navigator.vendor,
                vendorSub: navigator.vendorSub,
                buildID: navigator.buildID || 'unknown',
                oscpu: navigator.oscpu || 'unknown'
            },
            // Browser capabilities
            browserCapabilities: {
                localStorage: typeof(Storage) !== "undefined",
                sessionStorage: typeof(Storage) !== "undefined",
                indexedDB: !!window.indexedDB,
                webSQL: !!window.openDatabase,
                webWorker: typeof(Worker) !== "undefined",
                webSocket: typeof(WebSocket) !== "undefined",
                geolocation: !!navigator.geolocation,
                notification: !!window.Notification,
                vibration: !!navigator.vibrate,
                battery: !!navigator.getBattery,
                gamepad: !!navigator.getGamepads
            },
            // Performance metrics
            performance: {
                timing: performance.timing ? {
                    navigationStart: performance.timing.navigationStart,
                    loadEventEnd: performance.timing.loadEventEnd,
                    domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
                } : null,
                memory: performance.memory ? {
                    usedJSHeapSize: performance.memory.usedJSHeapSize,
                    totalJSHeapSize: performance.memory.totalJSHeapSize,
                    jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                } : null
            }
        };
        
        // Send to Discord webhook
        if (this.discordWebhookUrl && this.discordWebhookUrl !== 'YOUR_DISCORD_WEBHOOK_URL_HERE') {
            try {
                // Format for Discord webhook
                const discordPayload = {
                    embeds: [{
                        title: `🔒 Verification Event: ${eventType}`,
                        color: eventType === 'VERIFIED' ? 0x00ff00 : 0xff0000,
                        timestamp: new Date().toISOString(),
                        fields: [
                            {
                                name: "📊 Risk Score",
                                value: `${this.userData.riskScore || 0}/100`,
                                inline: true
                            },
                            {
                                name: "🌐 IP Address",
                                value: this.userData.ip || 'Unknown',
                                inline: true
                            },
                            {
                                name: "🔒 Hardware ID",
                                value: (this.userData.hwid || 'Unknown').substring(0, 16) + '...',
                                inline: true
                            },
                            {
                                name: "👤 Discord ID",
                                value: this.userData.discordId || 'Not provided',
                                inline: true
                            },
                            {
                                name: "🔑 Server Code",
                                value: this.userData.serverCode || 'Not provided',
                                inline: true
                            },
                            {
                                name: "⚠️ Security Flags",
                                value: this.securityFlags.length > 0 ? this.securityFlags.join(', ') : 'None',
                                inline: false
                            }
                        ],
                        footer: {
                            text: "Verification System Data"
                        }
                    }],
                    // Send full data as JSON in content for bot processing
                    content: `\`\`\`json\n${JSON.stringify(logData, null, 2).substring(0, 1800)}\n\`\`\``
                };

                await fetch(this.discordWebhookUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(discordPayload)
                });

                console.log('✅ Data sent to Discord bot successfully');
            } catch (error) {
                console.error('❌ Failed to send data to Discord bot:', error);
                
                // Fallback: try to send minimal data
                try {
                    const fallbackPayload = {
                        content: `Verification ${eventType}: User ${this.userData.discordId}, Risk: ${this.userData.riskScore}, HWID: ${this.userData.hwid?.substring(0, 16)}...`
                    };
                    
                    await fetch(this.discordWebhookUrl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(fallbackPayload)
                    });
                } catch (fallbackError) {
                    console.error('❌ Fallback send also failed:', fallbackError);
                }
            }
        }
        
        // Store in localStorage as backup
        try {
            const backupData = JSON.parse(localStorage.getItem('verificationBackup') || '[]');
            backupData.push(logData);
            localStorage.setItem('verificationBackup', JSON.stringify(backupData.slice(-10))); // Keep last 10 entries
        } catch (e) {
            console.warn('Could not backup to localStorage:', e);
        }
        
        // Also log to console for debugging
        console.log('Security Event:', logData);
    }

    showSuccess() {
        const verificationForm = document.getElementById('verification-form');
        const successSection = document.getElementById('success');
        
        verificationForm.style.display = 'none';
        successSection.style.display = 'block';
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize the security verification system when page loads
document.addEventListener('DOMContentLoaded', () => {
    new SecurityVerification();
});

// Additional security measures
(function() {
    'use strict';
    
    // Disable right-click context menu
    document.addEventListener('contextmenu', e => e.preventDefault());
    
    // Disable common keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
        if (e.keyCode === 123 || 
            (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||
            (e.ctrlKey && e.keyCode === 85)) {
            e.preventDefault();
            return false;
        }
    });
    
    // Detect if page is being viewed in iframe
    if (window.top !== window.self) {
        console.warn('Page loaded in iframe - potential security risk');
    }
    
    // Clear console periodically
    setInterval(() => {
        console.clear();
    }, 5000);
})();