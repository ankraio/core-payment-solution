package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type Dashboard struct {
	collector *Collector
	token     string
}

func NewDashboard(collector *Collector, token string) *Dashboard {
	return &Dashboard{collector: collector, token: token}
}

func (dashboard *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", dashboard.serveIndex)
	mux.HandleFunc("/api/sessions", dashboard.authed(dashboard.serveSessions))
	mux.HandleFunc("/api/events", dashboard.authed(dashboard.serveEvents))
	mux.HandleFunc("/api/report", dashboard.authed(dashboard.serveReport))
	return mux
}

func (dashboard *Dashboard) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		if dashboard.token != "" {
			provided := request.Header.Get("X-Auth-Token")
			if provided == "" {
				provided = request.URL.Query().Get("token")
			}
			if provided != dashboard.token {
				http.Error(responseWriter, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(responseWriter, request)
	}
}

func (dashboard *Dashboard) serveSessions(responseWriter http.ResponseWriter, request *http.Request) {
	records, queryError := dashboard.collector.Store().ListSessions(request.Context(), 200)
	if queryError != nil {
		http.Error(responseWriter, queryError.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(responseWriter, records)
}

func (dashboard *Dashboard) serveEvents(responseWriter http.ResponseWriter, request *http.Request) {
	events, queryError := dashboard.collector.Store().RecentEvents(request.Context(), 500)
	if queryError != nil {
		http.Error(responseWriter, queryError.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(responseWriter, events)
}

func (dashboard *Dashboard) serveReport(responseWriter http.ResponseWriter, request *http.Request) {
	sessionID := request.URL.Query().Get("session")
	sourceIP := request.URL.Query().Get("source")
	if sessionID == "" {
		http.Error(responseWriter, "session required", http.StatusBadRequest)
		return
	}
	report, buildError := dashboard.collector.BuildReport(context.Background(), sessionID, sourceIP)
	if buildError != nil {
		http.Error(responseWriter, buildError.Error(), http.StatusInternalServerError)
		return
	}
	if strings.Contains(request.Header.Get("Accept"), "text/markdown") || request.URL.Query().Get("format") == "md" {
		responseWriter.Header().Set("Content-Type", "text/markdown")
		_, _ = responseWriter.Write([]byte(report.Markdown()))
		return
	}
	writeJSON(responseWriter, report)
}

func (dashboard *Dashboard) serveIndex(responseWriter http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(responseWriter, request)
		return
	}
	responseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = responseWriter.Write([]byte(indexHTML))
}

func writeJSON(responseWriter http.ResponseWriter, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(responseWriter)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel - Honeypot Operations</title>
<style>
 body{font-family:ui-monospace,Menlo,monospace;background:#0b0e14;color:#c9d1d9;margin:0;padding:1.5rem}
 h1{color:#58a6ff;font-size:1.2rem}
 input{background:#161b22;color:#c9d1d9;border:1px solid #30363d;padding:.4rem;border-radius:4px}
 button{background:#238636;color:#fff;border:0;padding:.45rem .8rem;border-radius:4px;cursor:pointer}
 table{border-collapse:collapse;width:100%;margin-top:1rem;font-size:.82rem}
 th,td{border-bottom:1px solid #21262d;padding:.4rem .5rem;text-align:left}
 .sev-critical{color:#ff7b72;font-weight:bold}.sev-high{color:#ffa657}.sev-medium{color:#e3b341}.sev-low{color:#7ee787}
 pre{background:#161b22;padding:1rem;border-radius:6px;overflow:auto;max-height:50vh}
</style>
</head>
<body>
<h1>Core Payment Solution - Deception Sentinel</h1>
<p>Operator token: <input id="token" type="password" placeholder="X-Auth-Token"> <button onclick="refresh()">Load</button></p>
<div id="sessions"></div>
<h2>Selected session report</h2>
<pre id="report">select a session</pre>
<script>
function token(){return document.getElementById('token').value}
async function refresh(){
 const response = await fetch('/api/sessions?token='+encodeURIComponent(token()));
 if(!response.ok){document.getElementById('sessions').innerText='unauthorized';return}
 const rows = await response.json();
 let html = '<table><tr><th>session</th><th>source</th><th>severity</th><th>events</th><th>machines</th><th>last seen</th></tr>';
 for(const row of rows){
   const sev = (row.max_severity||'').toLowerCase();
   html += '<tr style="cursor:pointer" onclick="report(\''+row.id+'\',\''+row.source_ip+'\')">'+
     '<td>'+row.id+'</td><td>'+row.source_ip+'</td><td class="sev-'+sev+'">'+(row.max_severity||'')+'</td>'+
     '<td>'+row.event_count+'</td><td>'+(row.machines||[]).join(', ')+'</td><td>'+row.last_seen+'</td></tr>';
 }
 html += '</table>';
 document.getElementById('sessions').innerHTML = html;
}
async function report(session, source){
 const response = await fetch('/api/report?format=md&session='+session+'&source='+source+'&token='+encodeURIComponent(token()));
 document.getElementById('report').innerText = await response.text();
}
</script>
</body>
</html>`
