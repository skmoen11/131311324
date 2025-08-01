// Global variables
let testInProgress = false;
let mouseMovementData = [];
let scrollData = [];
let behaviorStartTime;
let fingerprint = '';
let canvasFingerprint = '';
let webglFingerprint = '';
let audioFingerprint = '';
let ipData = null;
let proxyData = null;
let emailData = null;
let dnsLeakData = null;

// DOM Elements
const runTestBtn = document.getElementById('runTestBtn');
const checkEmailBtn = document.getElementById('checkEmailBtn');
const emailInput = document.getElementById('emailInput');
const progressBar = document.getElementById('progressBar');
const progressText = document.getElementById('progressText');
const dnsLeakTestFrame = document.getElementById('dnsLeakTestFrame');

// Initialize the tool
document.addEventListener('DOMContentLoaded', function() {
    // Set up event listeners
    runTestBtn.addEventListener('click', runFullAnalysis);
    checkEmailBtn.addEventListener('click', checkEmail);
    
    // Set up behavior tracking
    setupBehaviorTracking();
    
    // Initialize some basic info
    updateBrowserLanguage();
    updateTimezone();
});

// Main function to run all tests
async function runFullAnalysis() {
    if (testInProgress) return;
    testInProgress = true;
    behaviorStartTime = Date.now();
    
    // Reset UI
    resetResults();
    runTestBtn.disabled = true;
    runTestBtn.innerHTML = '<i class="fas fa-spinner spinner"></i> Running Analysis...';
    
    try {
        // Update progress
        updateProgress(5, "Starting analysis...");
        
        // Run all tests sequentially
        await runDeviceFingerprintTests();
        await runNetworkTests();
        await runBehaviorAnalysis();
        
        // If email was checked before, include it in the final verdict
        if (emailData) {
            updateEmailResults();
        }
        
        // Generate final verdict
        generateFinalVerdict();
        
        updateProgress(100, "Analysis complete!");
    } catch (error) {
        console.error("Analysis error:", error);
        updateProgress(0, "Analysis failed");
        showError("Analysis failed. Please try again.");
    } finally {
        testInProgress = false;
        runTestBtn.disabled = false;
        runTestBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Run Again';
    }
}

// Device fingerprint tests
async function runDeviceFingerprintTests() {
    updateProgress(10, "Generating device fingerprint...");
    
    // Generate browser fingerprint
    fingerprint = await generateFingerprint();
    document.getElementById('fingerprintHash').textContent = fingerprint.substring(0, 12) + '...';
    setStatus('fingerprintStatus', 'safe');
    
    // Canvas fingerprint
    canvasFingerprint = getCanvasFingerprint();
    document.getElementById('canvasFingerprint').textContent = canvasFingerprint.substring(0, 12) + '...';
    setStatus('canvasStatus', 'safe');
    
    // WebGL fingerprint
    webglFingerprint = getWebGLFingerprint();
    document.getElementById('webglFingerprint').textContent = webglFingerprint.substring(0, 12) + '...';
    setStatus('webglStatus', 'safe');
    
    // Audio fingerprint
    audioFingerprint = getAudioFingerprint();
    document.getElementById('audioFingerprint').textContent = audioFingerprint.substring(0, 12) + '...';
    setStatus('audioStatus', 'safe');
    
    // Device memory
    const memory = navigator.deviceMemory || 'Unknown';
    document.getElementById('deviceMemory').textContent = memory + ' GB';
    setStatus('memoryStatus', memory >= 4 ? 'safe' : 'warning');
    
    updateProgress(25, "Device fingerprint complete");
}

// Network tests
async function runNetworkTests() {
    updateProgress(30, "Checking network information...");
    
    // Get IP and location data
    ipData = await fetchIPData();
    if (ipData) {
        document.getElementById('ipAddress').textContent = ipData.query;
        document.getElementById('location').textContent = `${ipData.city || 'Unknown'}, ${ipData.country}`;
        document.getElementById('isp').textContent = ipData.isp || 'Unknown';
        
        setStatus('ipStatus', 'safe');
        setStatus('locationStatus', 'safe');
        setStatus('ispStatus', 'safe');
        
        // Check for proxy/VPN/Tor
        await checkForProxy();
        
        // Check DNS leaks
        await checkDNSLeaks();
        
        // Check language mismatch
        checkLanguageMismatch();
        
        // Check timezone mismatch
        checkTimezoneMismatch();
    } else {
        setStatus('ipStatus', 'danger');
        setStatus('locationStatus', 'danger');
        setStatus('ispStatus', 'danger');
        document.getElementById('ipAddress').textContent = 'Failed to fetch';
        document.getElementById('location').textContent = 'Failed to fetch';
        document.getElementById('isp').textContent = 'Failed to fetch';
    }
    
    updateProgress(70, "Network tests complete");
}

// Behavior analysis
function runBehaviorAnalysis() {
    updateProgress(75, "Analyzing behavior patterns...");
    
    // Analyze mouse movements
    const mouseAnalysis = analyzeMouseMovements();
    document.getElementById('mousePattern').textContent = mouseAnalysis.pattern;
    setStatus('mouseStatus', mouseAnalysis.risk);
    
    // Analyze scroll behavior
    const scrollAnalysis = analyzeScrollBehavior();
    document.getElementById('scrollPattern').textContent = scrollAnalysis.pattern;
    setStatus('scrollStatus', scrollAnalysis.risk);
    
    // Analyze time patterns
    const timeAnalysis = analyzeTimePatterns();
    document.getElementById('timePattern').textContent = timeAnalysis.pattern;
    setStatus('timeStatus', timeAnalysis.risk);
    
    updateProgress(90, "Behavior analysis complete");
}

// Email verification
async function checkEmail() {
    const email = emailInput.value.trim();
    if (!email) return;
    
    checkEmailBtn.disabled = true;
    checkEmailBtn.innerHTML = '<i class="fas fa-spinner spinner"></i> Checking...';
    
    try {
        emailData = await verifyEmail(email);
        updateEmailResults();
        
        // If full analysis was already run, update the final verdict
        if (!testInProgress && document.getElementById('verdictTitle').textContent !== 'Analysis Not Run') {
            generateFinalVerdict();
        }
    } catch (error) {
        console.error("Email check error:", error);
        showError("Failed to verify email. Please try again.");
    } finally {
        checkEmailBtn.disabled = false;
        checkEmailBtn.innerHTML = '<i class="fas fa-envelope"></i> Check';
    }
}

function updateEmailResults() {
    if (!emailData) return;
    
    document.getElementById('emailDomain').textContent = emailData.domain;
    document.getElementById('mxRecords').textContent = emailData.mx ? 'Valid' : 'Invalid';
    document.getElementById('disposableEmail').textContent = emailData.disposable ? 'Yes' : 'No';
    document.getElementById('smtpCheck').textContent = emailData.smtp_check ? 'Valid' : 'Invalid';
    document.getElementById('emailRisk').textContent = emailData.riskScore + '/100';
    
    setStatus('domainStatus', emailData.disposable ? 'danger' : 'safe');
    setStatus('mxStatus', emailData.mx ? 'safe' : emailData.disposable ? 'danger' : 'warning');
    setStatus('disposableStatus', emailData.disposable ? 'danger' : 'safe');
    setStatus('smtpStatus', emailData.smtp_check ? 'safe' : emailData.disposable ? 'danger' : 'warning');
    setStatus('emailRiskStatus', 
        emailData.riskScore > 70 ? 'danger' : 
        emailData.riskScore > 30 ? 'warning' : 'safe');
}

// Generate final verdict based on all tests
function generateFinalVerdict() {
    const verdictElement = document.getElementById('verdictTitle');
    const verdictDescElement = document.getElementById('verdictDescription');
    const verdictIcon = document.getElementById('verdictIcon');
    const riskScoreElement = document.getElementById('riskScore');
    const detailedFindings = document.getElementById('detailedFindings');
    
    // Calculate overall risk score (0-100)
    let riskScore = 0;
    let riskFactors = [];
    let safeFactors = [];
    
    // Device fingerprint factors
    if (document.getElementById('memoryStatus').classList.contains('warning')) {
        riskScore += 10;
        riskFactors.push("Low device memory (may indicate virtual machine)");
    } else {
        safeFactors.push("Normal device memory");
    }
    
    // Network factors
    if (document.getElementById('proxyStatus').classList.contains('danger')) {
        riskScore += 30;
        riskFactors.push("Using VPN/Proxy/Tor (high risk)");
    } else if (document.getElementById('proxyStatus').classList.contains('warning')) {
        riskScore += 15;
        riskFactors.push("Possible proxy detected");
    } else {
        safeFactors.push("No VPN/Proxy detected");
    }
    
    if (document.getElementById('dnsStatus').classList.contains('danger')) {
        riskScore += 20;
        riskFactors.push("DNS leaks detected");
    } else {
        safeFactors.push("No DNS leaks detected");
    }
    
    if (document.getElementById('languageStatus').classList.contains('warning')) {
        riskScore += 10;
        riskFactors.push("Language/region mismatch");
    } else {
        safeFactors.push("Language matches location");
    }
    
    if (document.getElementById('timezoneStatus').classList.contains('warning')) {
        riskScore += 10;
        riskFactors.push("Timezone/location mismatch");
    } else {
        safeFactors.push("Timezone matches location");
    }
    
    // Behavior factors
    if (document.getElementById('mouseStatus').classList.contains('warning')) {
        riskScore += 5;
        riskFactors.push("Unnatural mouse movements");
    } else {
        safeFactors.push("Natural mouse movements");
    }
    
    if (document.getElementById('scrollStatus').classList.contains('warning')) {
        riskScore += 5;
        riskFactors.push("Unnatural scroll behavior");
    } else {
        safeFactors.push("Natural scroll behavior");
    }
    
    // Email factors (if checked)
    if (emailData) {
        if (emailData.disposable) {
            riskScore += 30;
            riskFactors.push("Disposable email detected");
        } else {
            safeFactors.push("Non-disposable email");
        }
        
        if (!emailData.mx) {
            riskScore += 15;
            riskFactors.push("Invalid email MX records");
        } else {
            safeFactors.push("Valid email MX records");
        }
    }
    
    // Cap at 100
    riskScore = Math.min(100, riskScore);
    
    // Determine verdict
    let verdict, description, iconClass;
    
    if (riskScore >= 70) {
        verdict = "High Risk";
        description = "Multiple high-risk factors detected. This setup would likely be flagged as fraudulent by CPA networks.";
        iconClass = "danger";
    } else if (riskScore >= 30) {
        verdict = "Moderate Risk";
        description = "Several risk factors detected. Some CPA networks might flag this setup for additional verification.";
        iconClass = "warning";
    } else {
        verdict = "Low Risk";
        description = "No significant risk factors detected. This setup appears legitimate to CPA networks.";
        iconClass = "safe";
    }
    
    // Update UI
    verdictElement.textContent = verdict;
    verdictDescElement.textContent = description;
    verdictIcon.className = "verdict-icon";
    verdictIcon.classList.add(iconClass);
    verdictIcon.innerHTML = `<i class="fas fa-${
        iconClass === 'danger' ? 'exclamation-triangle' : 
        iconClass === 'warning' ? 'exclamation-circle' : 'check-circle'
    }"></i>`;
    
    riskScoreElement.textContent = riskScore;
    document.getElementById('riskScoreCircle').style.background = `conic-gradient(
        var(--danger-color) 0% ${riskScore}%, 
        var(--success-color) ${riskScore}% 100%
    )`;
    
    // Show detailed findings
    detailedFindings.innerHTML = `
        <h4>Detailed Findings</h4>
        ${riskFactors.length > 0 ? `
            <p><strong>Risk Factors:</strong></p>
            <ul>
                ${riskFactors.map(factor => `<li class="danger"><i class="fas fa-times-circle"></i> ${factor}</li>`).join('')}
            </ul>
        ` : ''}
        ${safeFactors.length > 0 ? `
            <p><strong>Safe Indicators:</strong></p>
            <ul>
                ${safeFactors.map(factor => `<li class="safe"><i class="fas fa-check-circle"></i> ${factor}</li>`).join('')}
            </ul>
        ` : ''}
    `;
}

// Helper functions
function updateProgress(percent, message) {
    progressBar.style.width = `${percent}%`;
    progressText.textContent = message;
}

function setStatus(elementId, status) {
    const element = document.getElementById(elementId);
    element.className = 'status-badge';
    element.classList.add(status);
}

function resetResults() {
    // Reset all status indicators
    const statusBadges = document.querySelectorAll('.status-badge');
    statusBadges.forEach(badge => {
        badge.className = 'status-badge';
        badge.classList.add('unknown');
    });
    
    // Reset verdict
    document.getElementById('verdictTitle').textContent = 'Analysis In Progress';
    document.getElementById('verdictDescription').textContent = 'Running comprehensive fraud detection tests...';
    document.getElementById('verdictIcon').className = 'verdict-icon';
    document.getElementById('verdictIcon').innerHTML = '<i class="fas fa-spinner spinner"></i>';
    document.getElementById('riskScore').textContent = '0';
    document.getElementById('riskScoreCircle').style.background = 'conic-gradient(var(--danger-color) 0%, var(--warning-color) 50%, var(--success-color) 100%)';
    document.getElementById('detailedFindings').innerHTML = '';
}

function showError(message) {
    const verdictElement = document.getElementById('verdictTitle');
    const verdictDescElement = document.getElementById('verdictDescription');
    const verdictIcon = document.getElementById('verdictIcon');
    
    verdictElement.textContent = "Error";
    verdictDescElement.textContent = message;
    verdictIcon.className = "verdict-icon danger";
    verdictIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
}

// Device fingerprint functions
async function generateFingerprint() {
    return new Promise(resolve => {
        if (window.requestIdleCallback) {
            requestIdleCallback(() => {
                Fingerprint2.get(components => {
                    const values = components.map(component => component.value);
                    const fingerprint = Fingerprint2.x64hash128(values.join(''), 31);
                    resolve(fingerprint);
                });
            });
        } else {
            setTimeout(() => {
                Fingerprint2.get(components => {
                    const values = components.map(component => component.value);
                    const fingerprint = Fingerprint2.x64hash128(values.join(''), 31);
                    resolve(fingerprint);
                });
            }, 500);
        }
    });
}

function getCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        // Draw text with subtle differences
        ctx.textBaseline = "top";
        ctx.font = "14px 'Arial'";
        ctx.textBaseline = "alphabetic";
        ctx.fillStyle = "#f60";
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069";
        ctx.fillText("Canvas Fingerprint", 2, 15);
        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
        ctx.fillText("Canvas Fingerprint", 4, 17);
        
        // Add subtle canvas noise
        ctx.globalCompositeOperation = "multiply";
        ctx.fillStyle = "rgb(255,0,255)";
        ctx.beginPath();
        ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fill();
        ctx.fillStyle = "rgb(0,255,255)";
        ctx.beginPath();
        ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fill();
        ctx.fillStyle = "rgb(255,255,0)";
        ctx.beginPath();
        ctx.arc(75, 100, 50, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fill();
        ctx.fillStyle = "rgb(255,0,255)";
        ctx.arc(75, 75, 75, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.globalCompositeOperation = "source-over";
        ctx.fill();
        
        return canvas.toDataURL();
    } catch (e) {
        return "Error: " + e.message;
    }
}

function getWebGLFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        
        if (!gl) {
            return "WebGL not supported";
        }
        
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            return `${vendor} | ${renderer}`;
        }
        
        // Fallback to basic WebGL fingerprint
        const vertices = new Float32Array([-0.2, -0.9, 0, 0.4, -0.26, 0, 0, 0.732134444, 0]);
        const vertexBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, vertexBuffer);
        gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
        vertexBuffer.itemSize = 3;
        vertexBuffer.numItems = 3;
        
        const vs = `attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}`;
        const vertexShader = gl.createShader(gl.VERTEX_SHADER);
        gl.shaderSource(vertexShader, vs);
        gl.compileShader(vertexShader);
        
        const fs = `precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}`;
        const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
        gl.shaderSource(fragmentShader, fs);
        gl.compileShader(fragmentShader);
        
        const shaderProgram = gl.createProgram();
        gl.attachShader(shaderProgram, vertexShader);
        gl.attachShader(shaderProgram, fragmentShader);
        gl.linkProgram(shaderProgram);
        gl.useProgram(shaderProgram);
        
        shaderProgram.vertexPosAttrib = gl.getAttribLocation(shaderProgram, "attrVertex");
        shaderProgram.offsetUniform = gl.getUniformLocation(shaderProgram, "uniformOffset");
        
        gl.enableVertexAttribArray(shaderProgram.vertexPosArray);
        gl.vertexAttribPointer(shaderProgram.vertexPosAttrib, vertexBuffer.itemSize, gl.FLOAT, false, 0, 0);
        gl.uniform2f(shaderProgram.offsetUniform, 1, 1);
        
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, vertexBuffer.numItems);
        
        return canvas.toDataURL();
    } catch (e) {
        return "Error: " + e.message;
    }
}

function getAudioFingerprint() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        const gainNode = audioContext.createGain();
        const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
        
        let audioData = [];
        
        analyser.smoothingTimeConstant = 0.8;
        analyser.fftSize = 2048;
        
        oscillator.type = 'triangle';
        oscillator.frequency.value = 10000;
        
        gainNode.gain.value = 0;
        
        oscillator.connect(analyser);
        analyser.connect(scriptProcessor);
        scriptProcessor.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.start(0);
        
        scriptProcessor.onaudioprocess = function(e) {
            const buffer = new Uint8Array(analyser.frequencyBinCount);
            analyser.getByteFrequencyData(buffer);
            audioData.push(buffer.join(','));
            
            if (audioData.length >= 5) {
                scriptProcessor.disconnect();
                gainNode.disconnect();
                oscillator.disconnect();
                audioContext.close();
            }
        };
        
        return audioData.length > 0 ? audioData[0].substring(0, 50) + '...' : 'No audio data';
    } catch (e) {
        return "Error: " + e.message;
    }
}

// Network functions
async function fetchIPData() {
    try {
        const response = await fetch('https://ipapi.co/json/');
        if (!response.ok) throw new Error("IP API failed");
        return await response.json();
    } catch (e) {
        console.error("Failed to fetch IP data:", e);
        try {
            // Fallback to ip-api.com
            const response = await fetch('http://ip-api.com/json/');
            if (!response.ok) throw new Error("Fallback IP API failed");
            return await response.json();
        } catch (e2) {
            console.error("Fallback IP API also failed:", e2);
            return null;
        }
    }
}

async function checkForProxy() {
    if (!ipData || !ipData.ip) return;
    
    try {
        // Using IPQualityScore for proxy detection (free tier)
        const response = await fetch(`https://www.ipqualityscore.com/api/json/ip/YOUR_API_KEY/${ipData.ip}?strictness=1&allow_public_access_points=true&fast=true`);
        const data = await response.json();
        
        proxyData = data;
        
        let proxyStatus = 'safe';
        let proxyText = 'No VPN/Proxy detected';
        
        if (data.vpn || data.tor || data.proxy) {
            proxyStatus = 'danger';
            proxyText = 'VPN/Proxy/Tor detected';
        } else if (data.is_crawler || data.bot_status) {
            proxyStatus = 'warning';
            proxyText = 'Possible bot activity';
        } else if (data.active_vpn || data.active_tor) {
            proxyStatus = 'warning';
            proxyText = 'Possible VPN/Tor detected';
        }
        
        document.getElementById('proxyDetection').textContent = proxyText;
        setStatus('proxyStatus', proxyStatus);
    } catch (e) {
        console.error("Proxy check failed:", e);
        document.getElementById('proxyDetection').textContent = 'Proxy check failed';
        setStatus('proxyStatus', 'unknown');
    }
}

async function checkDNSLeaks() {
    return new Promise((resolve) => {
        // This is a simplified approach - in a real app you'd need a proper DNS leak test
        if (ipData && ipData.ip) {
            // Check if browser is using a known public DNS that doesn't match the ISP
            const knownPublicDNS = [
                '8.8.8.8', '8.8.4.4', // Google
                '1.1.1.1', '1.0.0.1', // Cloudflare
                '9.9.9.9', '149.112.112.112', // Quad9
                '208.67.222.222', '208.67.220.220' // OpenDNS
            ];
            
            // Get DNS servers from connection (this is limited in browsers)
            const dnsServers = [];
            
            // Check WebRTC leak (which can reveal local IP)
            let webrtcLeak = false;
            try {
                const rtc = new RTCPeerConnection({iceServers: []});
                rtc.createDataChannel('dnsleaktest');
                rtc.createOffer()
                    .then(offer => rtc.setLocalDescription(offer))
                    .catch(e => console.log(e));
                
                rtc.onicecandidate = (e) => {
                    if (e.candidate) {
                        const candidate = e.candidate.candidate;
                        if (candidate.includes('udp') && !candidate.includes(ipData.ip)) {
                            webrtcLeak = true;
                            dnsServers.push(candidate.split(' ')[4]);
                        }
                    }
                };
            } catch (e) {
                console.log("WebRTC not supported or blocked");
            }
            
            // Set timeout to check results
            setTimeout(() => {
                let dnsStatus = 'safe';
                let dnsText = 'No DNS leaks detected';
                
                if (webrtcLeak) {
                    dnsStatus = 'danger';
                    dnsText = 'WebRTC leak detected';
                } else if (dnsServers.length > 0 && knownPublicDNS.includes(dnsServers[0])) {
                    dnsStatus = 'warning';
                    dnsText = 'Using public DNS (' + dnsServers[0] + ')';
                }
                
                document.getElementById('dnsLeak').textContent = dnsText;
                setStatus('dnsStatus', dnsStatus);
                resolve();
            }, 2000);
        } else {
            document.getElementById('dnsLeak').textContent = 'DNS check failed';
            setStatus('dnsStatus', 'unknown');
            resolve();
        }
    });
}

function updateBrowserLanguage() {
    const language = navigator.language || navigator.userLanguage || 'Unknown';
    document.getElementById('browserLanguage').textContent = language;
}

function updateTimezone() {
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown';
    document.getElementById('timezone').textContent = timezone;
}

function checkLanguageMismatch() {
    if (!ipData || !ipData.country) return;
    
    const language = navigator.language || navigator.userLanguage || '';
    const countryCode = ipData.country;
    
    // Simple check - does the language match the country?
    // This is a very basic implementation - you'd want a more sophisticated check
    const languageMatches = language.includes(countryCode.toLowerCase()) || 
                          (countryCode === 'US' && language.includes('en')) ||
                          (countryCode === 'GB' && language.includes('en')) ||
                          (countryCode === 'DE' && language.includes('de')) ||
                          (countryCode === 'FR' && language.includes('fr')) ||
                          (countryCode === 'ES' && language.includes('es')) ||
                          (countryCode === 'IT' && language.includes('it')) ||
                          (countryCode === 'JP' && language.includes('ja')) ||
                          (countryCode === 'CN' && language.includes('zh')) ||
                          (countryCode === 'RU' && language.includes('ru'));
    
    setStatus('languageStatus', languageMatches ? 'safe' : 'warning');
}

function checkTimezoneMismatch() {
    if (!ipData || !ipData.timezone) return;
    
    const browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const ipTimezone = ipData.timezone;
    
    // Simple check - does the timezone roughly match?
    const timezoneMatches = browserTimezone && ipTimezone && 
                          (browserTimezone === ipTimezone || 
                           browserTimezone.replace(/^.*\//, '') === ipTimezone.replace(/^.*\//, ''));
    
    setStatus('timezoneStatus', timezoneMatches ? 'safe' : 'warning');
}

// Behavior tracking functions
function setupBehaviorTracking() {
    // Track mouse movements
    document.addEventListener('mousemove', (e) => {
        if (!testInProgress) return;
        
        mouseMovementData.push({
            x: e.clientX,
            y: e.clientY,
            time: Date.now()
        });
        
        // Keep only the last 50 movements
        if (mouseMovementData.length > 50) {
            mouseMovementData.shift();
        }
    });
    
    // Track scrolling
    let lastScrollTime = 0;
    document.addEventListener('scroll', () => {
        if (!testInProgress) return;
        
        const now = Date.now();
        scrollData.push({
            position: window.scrollY,
            time: now,
            timeSinceLast: lastScrollTime ? now - lastScrollTime : 0
        });
        
        lastScrollTime = now;
        
        // Keep only the last 20 scroll events
        if (scrollData.length > 20) {
            scrollData.shift();
        }
    });
}

function analyzeMouseMovements() {
    if (mouseMovementData.length < 5) {
        return {
            pattern: "Insufficient data",
            risk: "unknown"
        };
    }
    
    // Calculate movement angles and speeds
    let angles = [];
    let speeds = [];
    let straightLines = 0;
    
    for (let i = 1; i < mouseMovementData.length; i++) {
        const prev = mouseMovementData[i - 1];
        const curr = mouseMovementData[i];
        
        const dx = curr.x - prev.x;
        const dy = curr.y - prev.y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const timeDiff = curr.time - prev.time;
        const speed = timeDiff > 0 ? distance / timeDiff : 0;
        
        if (dx !== 0 || dy !== 0) {
            const angle = Math.atan2(dy, dx) * 180 / Math.PI;
            angles.push(angle);
        }
        
        speeds.push(speed);
        
        // Check for straight lines (common in bots)
        if (i > 2) {
            const prevAngle = angles[angles.length - 2];
            const currAngle = angles[angles.length - 1];
            if (Math.abs(currAngle - prevAngle) < 5) {
                straightLines++;
            }
        }
    }
    
    // Calculate statistics
    const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
    const speedVariance = speeds.reduce((a, b) => a + Math.pow(b - avgSpeed, 2), 0) / speeds.length;
    const angleChanges = [];
    
    for (let i = 1; i < angles.length; i++) {
        angleChanges.push(Math.abs(angles[i] - angles[i - 1]));
    }
    
    const avgAngleChange = angleChanges.reduce((a, b) => a + b, 0) / angleChanges.length;
    
    // Determine if behavior is human-like
    let pattern = "Natural movements";
    let risk = "safe";
    
    if (straightLines > mouseMovementData.length * 0.3) {
        pattern = "Overly straight movements";
        risk = "warning";
    } else if (avgAngleChange < 15 || avgAngleChange > 120) {
        pattern = "Unnatural angle changes";
        risk = "warning";
    } else if (speedVariance < 0.5 || speedVariance > 10) {
        pattern = "Unnatural speed variance";
        risk = "warning";
    }
    
    return {
        pattern,
        risk
    };
}

function analyzeScrollBehavior() {
    if (scrollData.length < 3) {
        return {
            pattern: "Insufficient data",
            risk: "unknown"
        };
    }
    
    // Calculate scroll statistics
    const timeDiffs = [];
    const positions = [];
    
    for (let i = 1; i < scrollData.length; i++) {
        timeDiffs.push(scrollData[i].timeSinceLast);
        positions.push(scrollData[i].position);
    }
    
    const avgTimeDiff = timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;
    const timeVariance = timeDiffs.reduce((a, b) => a + Math.pow(b - avgTimeDiff, 2), 0) / timeDiffs.length;
    
    // Check for perfectly regular scrolling (bot-like)
    let pattern = "Natural scrolling";
    let risk = "safe";
    
    if (timeVariance < 20) {
        pattern = "Overly regular scrolling";
        risk = "warning";
    } else if (positions.every(p => p > 0) && positions[positions.length - 1] - positions[0] > 500) {
        // Scrolled down a lot without any upward movement
        pattern = "One-directional scrolling";
        risk = "warning";
    }
    
    return {
        pattern,
        risk
    };
}

function analyzeTimePatterns() {
    if (!behaviorStartTime) {
        return {
            pattern: "Not analyzed",
            risk: "unknown"
        };
    }
    
    const totalTime = (Date.now() - behaviorStartTime) / 1000;
    let pattern = `Active for ${totalTime.toFixed(1)}s`;
    let risk = "safe";
    
    // Very short or very long sessions might be suspicious
    if (totalTime < 3) {
        pattern = "Very short session";
        risk = "warning";
    } else if (totalTime > 300) {
        pattern = "Very long session";
        risk = "warning";
    }
    
    return {
        pattern,
        risk
    };
}

// Email verification
async function verifyEmail(email) {
    try {
        // First check with Disify
        const disifyResponse = await fetch(`https://www.disify.com/api/email/${email}`);
        const disifyData = await disifyResponse.json();
        
        // Additional check with MailboxValidator (simulated)
        const mailboxData = {
            is_free: email.endsWith('@gmail.com') || 
                     email.endsWith('@yahoo.com') || 
                     email.endsWith('@outlook.com'),
            is_disposable: email.includes('temp-mail.org') || 
                          email.includes('mailinator.com') || 
                          email.includes('guerrillamail.com')
        };
        
        // Calculate risk score (0-100)
        let riskScore = 0;
        if (disifyData.disposable) riskScore += 70;
        if (!disifyData.mx) riskScore += 50;
        if (!disifyData.format) riskScore += 30;
        if (mailboxData.is_free) riskScore += 10;
        riskScore = Math.min(100, riskScore);
        
        return {
            email,
            domain: email.split('@')[1],
            format: disifyData.format,
            mx: disifyData.mx,
            smtp_check: disifyData.smtp_check,
            disposable: disifyData.disposable || mailboxData.is_disposable,
            is_free: mailboxData.is_free,
            riskScore
        };
    } catch (e) {
        console.error("Email verification error:", e);
        throw new Error("Email verification failed");
    }
}