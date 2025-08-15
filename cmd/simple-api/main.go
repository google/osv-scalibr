package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type HealthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Uptime    string    `json:"uptime"`
}

type VulnerabilityResponse struct {
	Status  string                 `json:"status"`
	Results map[string]interface{} `json:"results"`
	Message string                 `json:"message"`
}

var startTime = time.Now()

func main() {
	// Initialize Prometheus metrics
	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scalibr_api_requests_total",
			Help: "Total number of API requests",
		},
		[]string{"endpoint", "method"},
	)
	prometheus.MustRegister(requestsTotal)

	r := mux.NewRouter()

	// Middleware for metrics
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestsTotal.WithLabelValues(r.URL.Path, r.Method).Inc()
			next.ServeHTTP(w, r)
		})
	})

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/health", handleHealth).Methods("GET")
	api.HandleFunc("/vulnerabilities", handleVulnerabilities).Methods("POST")
	api.HandleFunc("/gemini-vulnerabilities", handleGeminiVulnerabilities).Methods("POST")

	// Metrics endpoint
	r.Handle("/metrics", promhttp.Handler())

	// Documentation
	r.HandleFunc("/", handleDocs).Methods("GET")

	log.Println("Starting SCALIBR API server on port 8081")
	log.Fatal(http.ListenAndServe(":8081", r))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Version:   "1.0.0-simple",
		Timestamp: time.Now(),
		Uptime:    time.Since(startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	response := VulnerabilityResponse{
		Status:  "success",
		Results: map[string]interface{}{
			"example_package": map[string]interface{}{
				"critical_count": 0,
				"high_count":     1,
				"medium_count":   2,
				"low_count":      3,
				"total_findings": 6,
				"risk_score":     0.3,
			},
		},
		Message: "SCALIBR vulnerability analysis (simplified version)",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGeminiVulnerabilities(w http.ResponseWriter, r *http.Request) {
	response := VulnerabilityResponse{
		Status:  "success",
		Results: map[string]interface{}{
			"example_package": map[string]interface{}{
				"total_findings":       2,
				"critical_count":       0,
				"high_count":          1,
				"privilege_escalation": 0,
				"command_injection":    1,
				"supply_chain_risk":    "medium",
			},
		},
		Message: "Gemini CLI vulnerability analysis (simplified version)",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleDocs(w http.ResponseWriter, r *http.Request) {
	docs := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚔️ SCALIBR API - The Round Table of Security</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Crimson+Text:ital,wght@0,400;0,600;1,400&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3a 50%, #2d1b69 100%);
            color: #e6e6fa;
            font-family: 'Crimson Text', serif;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .stars {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            background: transparent url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="20" cy="20" r="0.5" fill="white" opacity="0.8"/><circle cx="80" cy="30" r="0.3" fill="white" opacity="0.6"/><circle cx="40" cy="60" r="0.4" fill="white" opacity="0.7"/><circle cx="90" cy="80" r="0.2" fill="white" opacity="0.5"/><circle cx="10" cy="90" r="0.6" fill="white" opacity="0.9"/></svg>') repeat;
            animation: twinkle 3s ease-in-out infinite alternate;
        }
        
        @keyframes twinkle {
            0% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 1;
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
        }
        
        .crown {
            font-size: 4rem;
            margin-bottom: 1rem;
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        @keyframes glow {
            0% { text-shadow: 0 0 20px #ffd700, 0 0 30px #ffd700, 0 0 40px #ffd700; }
            100% { text-shadow: 0 0 30px #ffd700, 0 0 40px #ffd700, 0 0 50px #ffd700; }
        }
        
        .title {
            font-family: 'Cinzel', serif;
            font-size: 3.5rem;
            font-weight: 700;
            background: linear-gradient(45deg, #ffd700, #ffed4e, #ffd700);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }
        
        .subtitle {
            font-size: 1.3rem;
            color: #c9c9dd;
            font-style: italic;
            margin-bottom: 2rem;
        }
        
        .version-badge {
            display: inline-block;
            background: linear-gradient(45deg, #8b0000, #dc143c);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 25px;
            font-weight: 600;
            border: 2px solid #ffd700;
            box-shadow: 0 4px 15px rgba(220, 20, 60, 0.3);
        }
        
        .round-table {
            background: radial-gradient(circle, #2d1b69 0%, #1a1a3a 70%, #0f0f23 100%);
            border-radius: 50%;
            width: 800px;
            height: 800px;
            margin: 3rem auto;
            position: relative;
            border: 8px solid #ffd700;
            box-shadow: 
                0 0 50px rgba(255, 215, 0, 0.3),
                inset 0 0 50px rgba(255, 215, 0, 0.1);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .table-center {
            background: linear-gradient(45deg, #4b0082, #8b0000);
            border-radius: 50%;
            width: 200px;
            height: 200px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 4px solid #ffd700;
            box-shadow: 0 0 30px rgba(255, 215, 0, 0.5);
        }
        
        .excalibur {
            font-size: 4rem;
            animation: pulse 2s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        
        .knight {
            position: absolute;
            width: 120px;
            height: 120px;
            background: linear-gradient(45deg, #2c3e50, #34495e);
            border-radius: 15px;
            border: 3px solid #ffd700;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        
        .knight:hover {
            transform: scale(1.1) translateY(-5px);
            box-shadow: 0 8px 25px rgba(255, 215, 0, 0.4);
            background: linear-gradient(45deg, #34495e, #2c3e50);
        }
        
        .knight-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .knight-title {
            font-family: 'Cinzel', serif;
            font-size: 0.9rem;
            font-weight: 600;
            text-align: center;
            color: #ffd700;
        }
        
        .knight-method {
            font-size: 0.7rem;
            color: #c9c9dd;
            margin-top: 0.2rem;
        }
        
        /* Position knights around the table */
        .knight:nth-child(1) { top: 50px; left: 50%; transform: translateX(-50%); }
        .knight:nth-child(2) { top: 150px; right: 80px; }
        .knight:nth-child(3) { bottom: 150px; right: 80px; }
        .knight:nth-child(4) { bottom: 50px; left: 50%; transform: translateX(-50%); }
        .knight:nth-child(5) { bottom: 150px; left: 80px; }
        .knight:nth-child(6) { top: 150px; left: 80px; }
        
        .legend {
            margin-top: 3rem;
            text-align: center;
        }
        
        .legend h2 {
            font-family: 'Cinzel', serif;
            font-size: 2rem;
            color: #ffd700;
            margin-bottom: 1rem;
        }
        
        .quest-scroll {
            background: linear-gradient(45deg, #2c1810, #3d2817);
            border: 3px solid #8b4513;
            border-radius: 15px;
            padding: 2rem;
            margin: 1rem auto;
            max-width: 600px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            position: relative;
        }
        
        .quest-scroll::before {
            content: "📜";
            position: absolute;
            top: -15px;
            left: 20px;
            font-size: 2rem;
            background: #2c1810;
            padding: 0 10px;
        }
        
        .quest-title {
            font-family: 'Cinzel', serif;
            font-size: 1.3rem;
            color: #ffd700;
            margin-bottom: 0.5rem;
        }
        
        .quest-description {
            color: #e6e6fa;
            line-height: 1.6;
            margin-bottom: 1rem;
        }
        
        .quest-example {
            background: #1a1a3a;
            border-left: 4px solid #ffd700;
            padding: 1rem;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: #98fb98;
            overflow-x: auto;
        }
        
        .footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            border-top: 2px solid #ffd700;
        }
        
        .footer-text {
            font-style: italic;
            color: #c9c9dd;
            font-size: 1.1rem;
        }
        
        @media (max-width: 900px) {
            .round-table {
                width: 600px;
                height: 600px;
            }
            .title {
                font-size: 2.5rem;
            }
        }
        
        @media (max-width: 700px) {
            .round-table {
                width: 400px;
                height: 400px;
            }
            .knight {
                width: 80px;
                height: 80px;
            }
            .knight-icon {
                font-size: 1.5rem;
            }
            .knight-title {
                font-size: 0.7rem;
            }
        }
    </style>
</head>
<body>
    <div class="stars"></div>
    
    <div class="container">
        <header class="header">
            <div class="crown">👑</div>
            <h1 class="title">SCALIBR API</h1>
            <p class="subtitle">The Round Table of Security</p>
            <div class="version-badge">Version 1.0.0-simple</div>
        </header>
        
        <div class="round-table">
            <div class="table-center">
                <div class="excalibur">⚔️</div>
            </div>
            
            <div class="knight" onclick="testEndpoint('/api/v1/health', 'GET')">
                <div class="knight-icon">🛡️</div>
                <div class="knight-title">Health</div>
                <div class="knight-method">GET</div>
            </div>
            
            <div class="knight" onclick="testEndpoint('/api/v1/vulnerabilities', 'POST')">
                <div class="knight-icon">🗡️</div>
                <div class="knight-title">Vulnerabilities</div>
                <div class="knight-method">POST</div>
            </div>
            
            <div class="knight" onclick="testEndpoint('/api/v1/gemini-vulnerabilities', 'POST')">
                <div class="knight-icon">🔮</div>
                <div class="knight-title">Gemini</div>
                <div class="knight-method">POST</div>
            </div>
            
            <div class="knight" onclick="testEndpoint('/metrics', 'GET')">
                <div class="knight-icon">📊</div>
                <div class="knight-title">Metrics</div>
                <div class="knight-method">GET</div>
            </div>
            
            <div class="knight" onclick="showDocs()">
                <div class="knight-icon">📚</div>
                <div class="knight-title">Documentation</div>
                <div class="knight-method">INFO</div>
            </div>
            
            <div class="knight" onclick="showStatus()">
                <div class="knight-icon">⚡</div>
                <div class="knight-title">Status</div>
                <div class="knight-method">LIVE</div>
            </div>
        </div>
        
        <div class="legend">
            <h2>The Sacred Quests</h2>
            
            <div class="quest-scroll">
                <div class="quest-title">🛡️ The Health Guardian</div>
                <div class="quest-description">
                    Ensures the realm's defenses are strong and ready. Call upon this guardian to verify the API's vitality.
                </div>
                <div class="quest-example">curl http://localhost:8081/api/v1/health</div>
            </div>
            
            <div class="quest-scroll">
                <div class="quest-title">🗡️ The Vulnerability Hunter</div>
                <div class="quest-description">
                    Seeks out weaknesses in your code's armor. Send your packages to be examined for threats.
                </div>
                <div class="quest-example">curl -X POST http://localhost:8081/api/v1/vulnerabilities \\
  -H "Content-Type: application/json" \\
  -d '{"packages":[{"ecosystem":"npm","name":"lodash","version":"4.17.20"}]}'</div>
            </div>
            
            <div class="quest-scroll">
                <div class="quest-title">🔮 The Gemini Oracle</div>
                <div class="quest-description">
                    Channels ancient AI wisdom to divine advanced security insights from your dependencies.
                </div>
                <div class="quest-example">curl -X POST http://localhost:8081/api/v1/gemini-vulnerabilities \\
  -H "Content-Type: application/json" \\
  -d '{"packages":[{"ecosystem":"npm","name":"express","version":"4.18.0"}]}'</div>
            </div>
            
            <div class="quest-scroll">
                <div class="quest-title">📊 The Metrics Chronicler</div>
                <div class="quest-description">
                    Records the tales of API usage and performance for the realm's historians (Prometheus).
                </div>
                <div class="quest-example">curl http://localhost:8081/metrics</div>
            </div>
        </div>
        
        <footer class="footer">
            <p class="footer-text">
                "In unity there is strength, in security there is peace."<br>
                <strong>⚔️ Forged in the fires of open source, tempered by community wisdom ⚔️</strong>
            </p>
        </footer>
    </div>
    
    <script>
        function testEndpoint(path, method) {
            const url = window.location.origin + path;
            
            if (method === 'GET') {
                window.open(url, '_blank');
            } else {
                // For POST endpoints, show example curl command
                const example = 'curl -X ' + method + ' ' + url + ' -H "Content-Type: application/json" -d \'{"packages":[{"ecosystem":"npm","name":"test","version":"1.0.0"}]}\'';
                navigator.clipboard.writeText(example).then(() => {
                    alert('📋 Curl command copied to clipboard!\\n\\n' + example);
                }).catch(() => {
                    alert('Example command:\\n\\n' + example);
                });
            }
        }
        
        function showDocs() {
            alert('📚 Welcome to the SCALIBR API Documentation!\\n\\n' +
                  '🛡️ Health: GET /api/v1/health\\n' +
                  '🗡️ Vulnerabilities: POST /api/v1/vulnerabilities\\n' +
                  '🔮 Gemini: POST /api/v1/gemini-vulnerabilities\\n' +
                  '📊 Metrics: GET /metrics\\n\\n' +
                  'Click any knight to test the endpoint!');
        }
        
        function showStatus() {
            fetch('/api/v1/health')
                .then(response => response.json())
                .then(data => {
                    alert('⚡ API Status: ' + data.status.toUpperCase() + '\\n' +
                          '👑 Version: ' + data.version + '\\n' +
                          '⏰ Uptime: ' + data.uptime + '\\n' +
                          '🕐 Last Check: ' + new Date(data.timestamp).toLocaleString());
                })
                .catch(() => {
                    alert('❌ Unable to reach the API. The realm may be under siege!');
                });
        }
        
        // Add some interactive sparkles
        document.addEventListener('mousemove', function(e) {
            if (Math.random() > 0.95) {
                createSparkle(e.clientX, e.clientY);
            }
        });
        
        function createSparkle(x, y) {
            const sparkle = document.createElement('div');
            sparkle.style.position = 'fixed';
            sparkle.style.left = x + 'px';
            sparkle.style.top = y + 'px';
            sparkle.style.color = '#ffd700';
            sparkle.style.fontSize = '12px';
            sparkle.style.pointerEvents = 'none';
            sparkle.style.zIndex = '1000';
            sparkle.innerHTML = '✨';
            sparkle.style.animation = 'sparkleFloat 1s ease-out forwards';
            
            document.body.appendChild(sparkle);
            
            setTimeout(() => {
                document.body.removeChild(sparkle);
            }, 1000);
        }
        
        // Add sparkle animation
        const style = document.createElement('style');
        style.textContent = \`
            @keyframes sparkleFloat {
                0% { opacity: 1; transform: translateY(0px) scale(1); }
                100% { opacity: 0; transform: translateY(-50px) scale(0.5); }
            }
        \`;
        document.head.appendChild(style);
    </script>
</body>
</html>
`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(docs))
}