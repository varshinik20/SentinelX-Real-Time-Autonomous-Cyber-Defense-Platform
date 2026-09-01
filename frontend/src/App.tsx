import { useState, useEffect, useRef } from 'react';
import './App.css';

// Types representing backend schemas
interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  source: string;
  host: string;
  user: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  process_name: string | null;
  parent_process: string | null;
  severity: string;
  message: string;
  metadata: Record<string, any>;
}

interface DetectionAlert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  matched: boolean;
  confidence: number;
  risk_contribution: number;
  timestamp: string;
  host: string | null;
  user: string | null;
  message: string;
  evidence: Record<string, any>;
}

interface MitreTag {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
  evidence: string;
}

interface GraphNode {
  id: string;
  label: string;
  type: string;
  severity: number;
}

interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface Incident {
  incident_id: string;
  created_at: string;
  updated_at: string;
  severity: string;
  risk_score: number;
  status: string;
  host: string;
  user: string | null;
  source_ips: string[];
  related_event_ids: string[];
  related_alerts: DetectionAlert[];
  attack_techniques: MitreTag[];
  evidence: string[];
  recommendations: string[];
  attack_graph: AttackGraph;
  ai_summary: string | null;
}

interface SystemHealth {
  windows_collector: string;
  detection: string;
  correlation: string;
  websocket_clients: number;
  ai: string;
  response_mode: string;
  database: string;
  telemetry_mode: string;
  degraded: boolean;
  warnings: string[];
}

interface ResponseAction {
  action_id: string;
  incident_id: string;
  timestamp: string;
  action_type: string;
  target: string;
  reason: string;
  mode: string;
  status: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([]);
  const [health, setHealth] = useState<SystemHealth>({
    windows_collector: 'STOPPED',
    detection: 'STOPPED',
    correlation: 'STOPPED',
    websocket_clients: 0,
    ai: 'UNAVAILABLE',
    response_mode: 'DRY_RUN',
    database: 'DISCONNECTED',
    telemetry_mode: 'DEVELOPMENT',
    degraded: false,
    warnings: [],
  });
  
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [wsStatus, setWsStatus] = useState<string>('disconnected');
  
  // Search & filter states for Live Events
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial history on mount
  useEffect(() => {
    const fetchData = async () => {
      try {
        const hRes = await fetch('http://127.0.0.1:8000/health');
        if (hRes.ok) setHealth(await hRes.json());
        
        const eRes = await fetch('http://127.0.0.1:8000/api/events');
        if (eRes.ok) setEvents(await eRes.json());

        const iRes = await fetch('http://127.0.0.1:8000/api/incidents');
        if (iRes.ok) setIncidents(await iRes.json());

        const rRes = await fetch('http://127.0.0.1:8000/api/response/actions');
        if (rRes.ok) setResponseActions(await rRes.json());
      } catch (err) {
        console.error('Failed to load initial data from backend API:', err);
      }
    };

    fetchData();
  }, [activeTab]);

  // WebSocket connection & handler logic
  useEffect(() => {
    const connectWS = () => {
      setWsStatus('connecting');
      const ws = new WebSocket('ws://127.0.0.1:8000/ws/events');
      wsRef.current = ws;

      ws.onopen = () => {
        setWsStatus('connected');
        console.log('[WEBSOCKET] Connected to real-time telemetry stream.');
      };

      ws.onmessage = (msgEvent) => {
        try {
          const payload = JSON.parse(msgEvent.data);
          const type = payload.message_type;
          const data = payload.data;

          if (type === 'EVENT') {
            setEvents((prev) => [data, ...prev.slice(0, 499)]);
          } else if (type === 'INCIDENT') {
            setIncidents((prev) => {
              const exists = prev.some((i) => i.incident_id === data.incident_id);
              if (exists) {
                return prev.map((i) => (i.incident_id === data.incident_id ? data : i));
              }
              return [data, ...prev];
            });
            
            fetch('http://127.0.0.1:8000/api/response/actions')
              .then((r) => r.json())
              .then((actions) => setResponseActions(actions))
              .catch((e) => console.error(e));
          } else if (type === 'STATUS') {
            setHealth(data);
          }
        } catch (err) {
          console.error('[WEBSOCKET] Error parsing message:', err);
        }
      };

      ws.onclose = () => {
        setWsStatus('disconnected');
        console.log('[WEBSOCKET] Disconnected. Reconnecting in 3s...');
        setTimeout(connectWS, 3000);
      };

      ws.onerror = (err) => {
        console.error('[WEBSOCKET] Error occurred:', err);
        ws.close();
      };
    };

    connectWS();

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const activeIncidents = incidents.filter((i) => i.status !== 'RESOLVED');
  const maxRiskIncident = incidents.reduce((max, i) => (i.risk_score > (max?.risk_score || 0) ? i : max), null as Incident | null);

  return (
    <div className="dashboard-container">
      {/* Sidebar Navigation */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">🛡️ SENTINELX</div>
          <span className={`indicator-dot ${wsStatus === 'connected' ? 'active' : 'inactive'}`} />
        </div>
        
        <div className="sidebar-menu">
          <div className={`menu-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
            📺 Command Center
          </div>
          <div className={`menu-item ${activeTab === 'events' ? 'active' : ''}`} onClick={() => setActiveTab('events')}>
            📟 Live Event Feed
          </div>
          <div className={`menu-item ${activeTab === 'incidents' ? 'active' : ''}`} onClick={() => { setActiveTab('incidents'); setSelectedIncidentId(null); }}>
            🚨 Incidents ({activeIncidents.length})
          </div>
          <div className={`menu-item ${activeTab === 'audit' ? 'active' : ''}`} onClick={() => setActiveTab('audit')}>
            ⚙️ Response Audit
          </div>
          <div className={`menu-item ${activeTab === 'health' ? 'active' : ''}`} onClick={() => setActiveTab('health')}>
            ❤️ System Health
          </div>
        </div>

        <div className="sidebar-footer">
          <div>Socket: <span className="mono-text" style={{ color: wsStatus === 'connected' ? 'var(--accent-green)' : 'var(--accent-red)' }}>{wsStatus.toUpperCase()}</span></div>
          <div style={{ marginTop: '6px' }}>Asset Scope: <span className="mono-text">LOCAL WINDOWS</span></div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="main-content">
        <div className="header">
          <div className="header-title">
            {activeTab === 'dashboard' && 'SYSTEM OVERVIEW & SECURITY POSTURE'}
            {activeTab === 'events' && 'LIVE STREAMING TELEMETRY BUS'}
            {activeTab === 'incidents' && (selectedIncidentId ? 'INCIDENT CYBER-FORENSIC INVESTIGATION' : 'INCIDENT CORRELATION LIFE CYCLE')}
            {activeTab === 'audit' && 'SIMULATED RESPONDER ACTION AUDITING'}
            {activeTab === 'health' && 'AGENT MODULE TELEMETRY MATRIX'}
          </div>
          <div style={{ fontSize: '13px', fontWeight: 'bold' }}>
            STATUS: {health.degraded ? <span style={{ color: 'var(--accent-orange)' }}>DEGRADED</span> : <span style={{ color: 'var(--accent-green)' }}>PROTECTED</span>}
          </div>
        </div>

        <div className="content-pane">
          {activeTab === 'dashboard' && (
            <CommandCenter 
              events={events} 
              activeIncidents={activeIncidents} 
              maxRiskIncident={maxRiskIncident} 
              setActiveTab={setActiveTab}
              setSelectedIncidentId={setSelectedIncidentId}
            />
          )}

          {activeTab === 'events' && (
            <LiveEventsView 
              events={events} 
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              severityFilter={severityFilter}
              setSeverityFilter={setSeverityFilter}
              typeFilter={typeFilter}
              setTypeFilter={setTypeFilter}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentsView 
              incidents={incidents} 
              selectedIncidentId={selectedIncidentId} 
              setSelectedIncidentId={setSelectedIncidentId}
            />
          )}

          {activeTab === 'audit' && (
            <ResponseAuditView actions={responseActions} />
          )}

          {activeTab === 'health' && (
            <SystemHealthView health={health} />
          )}
        </div>
      </div>
    </div>
  );
}

// Sub-component: Command Center Tab
interface CommandCenterProps {
  events: SecurityEvent[];
  activeIncidents: Incident[];
  maxRiskIncident: Incident | null;
  setActiveTab: (tab: string) => void;
  setSelectedIncidentId: (id: string | null) => void;
}

function CommandCenter({ events, activeIncidents, maxRiskIncident, setActiveTab, setSelectedIncidentId }: CommandCenterProps) {
  const uniqueHosts = new Set(events.map((e) => e.host)).size;
  const uniqueUsers = new Set(events.filter((e) => e.user).map((e) => e.user)).size;

  return (
    <div className="animate-slide-in">
      {/* Metrics Row */}
      <div className="metrics-grid">
        <div className="metric-card cyber-panel">
          <div className="metric-header" style={{ color: 'var(--accent-cyan)' }}>Telemetry Bus Rate</div>
          <div className="metric-value">{events.length > 0 ? (events.length / 60).toFixed(1) : 0} <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>eps</span></div>
        </div>
        <div className="metric-card cyber-panel">
          <div className="metric-header" style={{ color: 'var(--accent-red)' }}>Active Threat Files</div>
          <div className="metric-value" style={{ color: activeIncidents.length > 0 ? 'var(--accent-red)' : 'var(--text-primary)' }}>
            {activeIncidents.length}
          </div>
        </div>
        <div className="metric-card cyber-panel">
          <div className="metric-header" style={{ color: 'var(--accent-orange)' }}>Highest Asset Risk</div>
          <div className="metric-value" style={{ color: maxRiskIncident ? getRiskColor(maxRiskIncident.risk_score) : 'var(--text-primary)' }}>
            {maxRiskIncident ? maxRiskIncident.risk_score : 0}<span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>/100</span>
          </div>
        </div>
        <div className="metric-card cyber-panel">
          <div className="metric-header" style={{ color: 'var(--accent-green)' }}>Active Domain Users</div>
          <div className="metric-value">{uniqueUsers}</div>
        </div>
        <div className="metric-card cyber-panel">
          <div className="metric-header" style={{ color: 'var(--accent-purple)' }}>Monitored Endpoints</div>
          <div className="metric-value">{uniqueHosts} <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>assets</span></div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '20px', marginTop: '20px' }}>
        {/* Active Incident List */}
        <div className="cyber-panel" style={{ padding: '24px' }}>
          <h3 style={{ margin: '0 0 20px 0', fontSize: '16px', letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--accent-cyan)' }}>🔥 Live Correlated Attacks</h3>
          <div className="table-container">
            {activeIncidents.length === 0 ? (
              <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>No active threats detected. Sandbox environment is secure.</div>
            ) : (
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Target Host</th>
                    <th>User Session</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {activeIncidents.slice(0, 5).map((inc) => (
                    <tr key={inc.incident_id}>
                      <td>
                        <span className={`badge badge-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                      </td>
                      <td style={{ fontWeight: '700', fontFamily: 'Fira Code', color: getRiskColor(inc.risk_score) }}>{inc.risk_score}</td>
                      <td className="mono-text">{inc.host}</td>
                      <td>{inc.user || '-'}</td>
                      <td>
                        <button 
                          style={{ background: 'transparent', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold', fontSize: '11px', textTransform: 'uppercase' }}
                          onClick={() => {
                            setSelectedIncidentId(inc.incident_id);
                            setActiveTab('incidents');
                          }}
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Real-time Terminal Logger */}
        <div className="cyber-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', height: '400px' }}>
          <h3 style={{ margin: '0 0 20px 0', fontSize: '16px', letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--accent-purple)' }}>📟 Live Normalizer Pipeline Feed</h3>
          <div className="mono-text" style={{ flex: 1, backgroundColor: '#020409', borderRadius: '4px', padding: '16px', overflowY: 'auto', fontSize: '11px', color: '#00ff66', display: 'flex', flexDirection: 'column-reverse', border: '1px solid rgba(255,255,255,0.05)' }}>
            {events.slice(0, 100).map((e) => (
              <div key={e.event_id} style={{ marginBottom: '6px', lineBreak: 'anywhere' }}>
                <span style={{ color: '#4b5563' }}>[{new Date(e.timestamp).toLocaleTimeString()}]</span>{' '}
                <span style={{ color: e.severity === 'HIGH' || e.severity === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>
                  {e.event_type}
                </span>{' '}
                - {e.message}
              </div>
            ))}
            {events.length === 0 && <div style={{ color: 'var(--text-muted)' }}>Waiting for Windows Event API logs...</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

// Sub-component: Live Events Tab
interface LiveEventsProps {
  events: SecurityEvent[];
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  severityFilter: string;
  setSeverityFilter: (filter: string) => void;
  typeFilter: string;
  setTypeFilter: (filter: string) => void;
}

function LiveEventsView({ events, searchQuery, setSearchQuery, severityFilter, setSeverityFilter, typeFilter, setTypeFilter }: LiveEventsProps) {
  const eventTypes = Array.from(new Set(events.map((e) => e.event_type)));

  const filteredEvents = events.filter((e) => {
    const matchesSearch = e.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.user && e.user.toLowerCase().includes(searchQuery.toLowerCase())) ||
      e.host.toLowerCase().includes(searchQuery.toLowerCase());
      
    const matchesSeverity = severityFilter === 'ALL' || e.severity === severityFilter;
    const matchesType = typeFilter === 'ALL' || e.event_type === typeFilter;
    
    return matchesSearch && matchesSeverity && matchesType;
  });

  return (
    <div className="cyber-panel animate-slide-in" style={{ padding: '24px' }}>
      {/* Filters Row */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '24px', flexWrap: 'wrap' }}>
        <input 
          type="text" 
          placeholder="Filter logs by keyword, host, session..." 
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{ flex: 1, minWidth: '200px', backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '10px 16px', color: 'var(--text-primary)', outline: 'none' }}
        />
        <select 
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '10px 16px', color: 'var(--text-primary)', outline: 'none', fontWeight: 'bold' }}
        >
          <option value="ALL">All Severities</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
        <select 
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '10px 16px', color: 'var(--text-primary)', outline: 'none', fontWeight: 'bold' }}
        >
          <option value="ALL">All Event Types</option>
          {eventTypes.map((type) => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
      </div>

      {/* Events Table */}
      <div className="table-container">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Host</th>
              <th>User</th>
              <th>Event Message Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((e) => (
              <tr key={e.event_id}>
                <td className="mono-text" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{new Date(e.timestamp).toLocaleString()}</td>
                <td><span style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>{e.event_type}</span></td>
                <td>
                  <span className={`badge badge-${e.severity.toLowerCase()}`}>{e.severity}</span>
                </td>
                <td className="mono-text">{e.host}</td>
                <td>{e.user || '-'}</td>
                <td style={{ fontSize: '12px', maxWidth: '350px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>{e.message}</td>
              </tr>
            ))}
            {filteredEvents.length === 0 && (
              <tr>
                <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>No matching telemetry events.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Sub-component: Incidents Tab
interface IncidentsViewProps {
  incidents: Incident[];
  selectedIncidentId: string | null;
  setSelectedIncidentId: (id: string | null) => void;
}

function IncidentsView({ incidents, selectedIncidentId, setSelectedIncidentId }: IncidentsViewProps) {
  const selectedIncident = incidents.find((i) => i.incident_id === selectedIncidentId);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedIncidentId ? '320px 1fr' : '1fr', gap: '20px' }} className="animate-slide-in">
      {/* Sidebar List */}
      <div className="cyber-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 style={{ margin: '0 0 10px 0', fontSize: '16px', color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Correlated Incidents</h3>
        {incidents.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', padding: '20px 0' }}>No incidents triaged yet.</div>
        ) : (
          incidents.map((inc) => (
            <div 
              key={inc.incident_id}
              className="cyber-panel"
              onClick={() => setSelectedIncidentId(inc.incident_id)}
              style={{
                padding: '16px',
                cursor: 'pointer',
                borderLeft: `4px solid ${getRiskColor(inc.risk_score)}`,
                backgroundColor: selectedIncidentId === inc.incident_id ? 'rgba(6,182,212,0.03)' : 'transparent',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span className="mono-text" style={{ fontSize: '11px', fontWeight: 'bold' }}>{inc.incident_id.slice(0, 8)}</span>
                <span className={`badge badge-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
              </div>
              <div style={{ fontSize: '13px', fontWeight: 'bold' }}>Host: {inc.host}</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                <span>Risk: <b style={{ color: getRiskColor(inc.risk_score) }}>{inc.risk_score}</b></span>
                <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Incident Detail Investigation View */}
      {selectedIncidentId && selectedIncident ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Card: Header Details */}
          <div className="cyber-panel" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <span className="mono-text" style={{ color: 'var(--text-muted)', fontSize: '11px' }}>ID: {selectedIncident.incident_id}</span>
                <h2 style={{ margin: '6px 0 0 0', fontSize: '20px', letterSpacing: '0.5px' }}>Compromise Analysis: {selectedIncident.host}</h2>
              </div>
              <div className="risk-dial-container">
                <svg width="110" height="110">
                  <circle cx="55" cy="55" r="48" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="6" />
                  <circle 
                    cx="55" 
                    cy="55" 
                    r="48" 
                    fill="none" 
                    stroke={getRiskColor(selectedIncident.risk_score)} 
                    strokeWidth="6" 
                    strokeDasharray="301.59"
                    strokeDashoffset={301.59 - (301.59 * selectedIncident.risk_score) / 100}
                    transform="rotate(-90 55 55)"
                  />
                </svg>
                <div className="risk-dial-label" style={{ color: getRiskColor(selectedIncident.risk_score) }}>
                  {selectedIncident.risk_score}
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>SEVERITY</div>
                <div style={{ fontWeight: '700', marginTop: '4px' }}>
                  <span className={`badge badge-${selectedIncident.severity.toLowerCase()}`}>{selectedIncident.severity}</span>
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>INCIDENT STATUS</div>
                <div style={{ fontWeight: '700', marginTop: '4px', color: 'var(--accent-cyan)', fontSize: '12px' }}>{selectedIncident.status}</div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>TARGET ACCOUNT</div>
                <div style={{ fontWeight: '700', marginTop: '4px', fontSize: '12px' }}>{selectedIncident.user || 'Unknown'}</div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>ATTACK SOURCE IPS</div>
                <div style={{ fontWeight: '700', marginTop: '4px', fontSize: '12px' }}>{selectedIncident.source_ips.join(', ') || '127.0.0.1'}</div>
              </div>
            </div>
          </div>

          {/* Interactive SVG Attack Graph */}
          <div className="cyber-panel" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '14px', color: 'var(--accent-cyan)', textTransform: 'uppercase' }}>🛡️ Attack Graph Flow</h3>
            <AttackGraphRenderer graph={selectedIncident.attack_graph} />
          </div>

          {/* MITRE ATT&CK Matrix Heatmap */}
          <div className="cyber-panel" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '14px', color: 'var(--accent-orange)', textTransform: 'uppercase' }}>🗺️ MITRE ATT&CK Matrix Heatmap</h3>
            <MitreMatrix activeTechniques={selectedIncident.attack_techniques} />
          </div>

          {/* Card: AI Investigation & Recommendations */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px' }}>
            <div className="cyber-panel" style={{ padding: '24px', borderLeft: '4px solid var(--accent-purple)' }}>
              <h3 style={{ margin: '0 0 12px 0', color: 'var(--accent-purple)', fontSize: '14px' }}>🤖 AI Copilot Analysis</h3>
              <p style={{ fontSize: '13px', lineHeight: '1.6', margin: '0', color: 'var(--text-secondary)' }}>{selectedIncident.ai_summary || 'Analyzing evidence...'}</p>
            </div>
            
            <div className="cyber-panel" style={{ padding: '24px', borderLeft: '4px solid var(--accent-green)' }}>
              <h3 style={{ margin: '0 0 12px 0', color: 'var(--accent-green)', fontSize: '14px' }}>🛡️ Containment Recommendations</h3>
              <ul style={{ paddingLeft: '18px', margin: '0', fontSize: '12px', lineHeight: '1.7', color: 'var(--text-secondary)' }}>
                {selectedIncident.recommendations.map((rec, index) => (
                  <li key={index} style={{ marginBottom: '6px' }}>{rec}</li>
                ))}
                {selectedIncident.recommendations.length === 0 && <li>Formulating defense actions...</li>}
              </ul>
            </div>
          </div>

          {/* Card: Chronological Timeline */}
          <div className="cyber-panel" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 20px 0', fontSize: '14px', color: 'var(--accent-cyan)' }}>⏳ Timeline of Mapped Events</h3>
            <div className="timeline">
              {selectedIncident.related_alerts.map((al) => (
                <div key={al.alert_id} className="timeline-item" style={{ marginBottom: '10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                    <span style={{ fontWeight: '700', color: 'var(--accent-orange)' }}>Alert triggered: {al.rule_name}</span>
                    <span className="mono-text" style={{ color: 'var(--text-muted)' }}>{new Date(al.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>{al.message}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="cyber-panel" style={{ padding: '80px', textAlign: 'center', color: 'var(--text-secondary)' }}>
          Select an incident from the listing panel to begin the analysis.
        </div>
      )}
    </div>
  );
}

// Sub-component: Attack Graph Renderer (SVG Node-Link diagram with glowing and flow animations)
interface AttackGraphRendererProps {
  graph: AttackGraph;
}

function AttackGraphRenderer({ graph }: AttackGraphRendererProps) {
  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return <div style={{ height: '350px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>No attack graph available.</div>;
  }

  const width = 800;
  const height = 400;

  // Determine Layering for nodes
  const layerMap: Record<string, number> = {
    ip: 0,
    user: 1,
    host: 1,
    process: 2,
    file: 3,
    alert: 3,
    unknown: 2,
  };

  const layers: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [] };
  graph.nodes.forEach((n) => {
    const l = layerMap[n.type] ?? 2;
    layers[l].push(n);
  });

  // Calculate coordinates
  const nodeCoords: Record<string, { x: number; y: number }> = {};
  [0, 1, 2, 3].forEach((lNum) => {
    const list = layers[lNum];
    const n_nodes = list.length;
    const x = 70 + lNum * 220;
    list.forEach((node, idx) => {
      const y = (idx + 1) * (height / (n_nodes + 1));
      nodeCoords[node.id] = { x, y };
    });
  });

  // Icon mapper helper
  const getNodeIcon = (type: string) => {
    if (type === 'ip') return '🌐';
    if (type === 'user') return '👤';
    if (type === 'host') return '🖥️';
    if (type === 'process') return '⚙️';
    if (type === 'alert') return '⚠️';
    return '📄';
  };

  const getNodeColor = (type: string) => {
    if (type === 'ip') return 'var(--accent-purple)';
    if (type === 'user') return 'var(--accent-green)';
    if (type === 'host') return 'var(--accent-cyan)';
    if (type === 'process') return 'var(--accent-orange)';
    if (type === 'alert') return 'var(--accent-red)';
    return 'var(--text-muted)';
  };

  return (
    <div className="attack-graph-pane" style={{ position: 'relative' }}>
      <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} style={{ background: '#05070e' }}>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.18)" />
          </marker>
        </defs>

        {/* Draw Edges with Flow Animation */}
        {graph.edges.map((edge, idx) => {
          const from = nodeCoords[edge.source];
          const to = nodeCoords[edge.target];
          if (!from || !to) return null;
          return (
            <g key={`edge-${idx}`}>
              <line 
                x1={from.x} y1={from.y} 
                x2={to.x} y2={to.y} 
                stroke="rgba(6, 182, 212, 0.25)" 
                strokeWidth="1.5" 
                className="flowing-line"
                markerEnd="url(#arrow)" 
              />
              <text 
                x={(from.x + to.x) / 2} 
                y={(from.y + to.y) / 2 - 5} 
                fill="var(--text-secondary)" 
                fontSize="8" 
                textAnchor="middle"
                className="mono-text"
              >
                {edge.relation}
              </text>
            </g>
          );
        })}

        {/* Draw Nodes */}
        {graph.nodes.map((node) => {
          const coord = nodeCoords[node.id];
          if (!coord) return null;
          const color = getNodeColor(node.type);
          return (
            <g key={node.id} transform={`translate(${coord.x}, ${coord.y})`}>
              <circle 
                r="16" 
                fill="#0a0f1d" 
                stroke={color} 
                strokeWidth="2" 
                style={{ filter: `drop-shadow(0px 0px 6px ${color})` }} 
              />
              <text 
                y="4"
                textAnchor="middle"
                fontSize="12"
              >
                {getNodeIcon(node.type)}
              </text>
              <text 
                y="-22" 
                fill="var(--text-primary)" 
                fontSize="10" 
                fontWeight="bold"
                textAnchor="middle"
              >
                {node.label.length > 20 ? node.label.slice(0, 17) + '...' : node.label}
              </text>
              <text 
                y="30" 
                fill="var(--text-muted)" 
                fontSize="8" 
                textAnchor="middle"
                className="mono-text"
              >
                {node.type.toUpperCase()}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// Sub-component: MITRE ATT&CK Matrix Heatmap Component
interface MitreMatrixProps {
  activeTechniques: MitreTag[];
}

function MitreMatrix({ activeTechniques }: MitreMatrixProps) {
  // Define columns representing MITRE ATT&CK tactics
  const matrixData = [
    {
      tactic: "Execution",
      techniques: [
        { id: "T1059", name: "Command Interpreter" },
        { id: "T1204", name: "User Execution" },
      ]
    },
    {
      tactic: "Persistence",
      techniques: [
        { id: "T1543", name: "System Process Modification" },
        { id: "T1547", name: "Boot Auto-Start Execution" },
      ]
    },
    {
      tactic: "Privilege Escalation",
      techniques: [
        { id: "T1078", name: "Valid Accounts" },
        { id: "T1548", name: "Bypass UAC Access Control" },
      ]
    },
    {
      tactic: "Credential Access",
      techniques: [
        { id: "T1110", name: "Brute Force Stuffing" },
        { id: "T1555", name: "Credential Manager Read" },
      ]
    },
    {
      tactic: "Discovery",
      techniques: [
        { id: "T1033", name: "System Account Discovery" },
        { id: "T1082", name: "System Information Discovery" },
      ]
    },
  ];

  const isActive = (techId: string) => {
    return activeTechniques.some((t) => t.technique_id === techId);
  };

  return (
    <div className="mitre-grid">
      {matrixData.map((col, idx) => (
        <div key={idx} className="mitre-column">
          <div className="mitre-column-title">{col.tactic}</div>
          {col.techniques.map((tech) => {
            const active = isActive(tech.id);
            return (
              <div 
                key={tech.id} 
                className={`mitre-cell ${active ? 'active' : ''}`}
              >
                <div>{tech.name}</div>
                <div className="mono-text" style={{ fontSize: '8px', opacity: 0.6, marginTop: '4px' }}>{tech.id}</div>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

// Sub-component: Response Audit Tab
interface ResponseAuditViewProps {
  actions: ResponseAction[];
}

function ResponseAuditView({ actions }: ResponseAuditViewProps) {
  return (
    <div className="cyber-panel animate-slide-in" style={{ padding: '24px' }}>
      <h3 style={{ margin: '0 0 16px 0', fontSize: '15px', color: 'var(--accent-cyan)' }}>Audited Threat Response Log</h3>
      <div className="table-container">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action ID</th>
              <th>Containment Control</th>
              <th>Target Asset</th>
              <th>Reason for Policy Action</th>
              <th>Policy Mode</th>
              <th>Execution Status</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((act) => (
              <tr key={act.action_id}>
                <td className="mono-text" style={{ fontSize: '11px' }}>{new Date(act.timestamp).toLocaleString()}</td>
                <td className="mono-text" style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{act.action_id.slice(0, 8)}</td>
                <td><span style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>{act.action_type}</span></td>
                <td><span className="mono-text">{act.target}</span></td>
                <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{act.reason}</td>
                <td>
                  <span style={{ padding: '2px 6px', backgroundColor: 'rgba(6,182,212,0.05)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '9px', fontWeight: 'bold' }}>
                    {act.mode}
                  </span>
                </td>
                <td>
                  <span style={{ color: 'var(--accent-green)', fontWeight: 'bold', fontSize: '11px' }}>
                    {act.status}
                  </span>
                </td>
              </tr>
            ))}
            {actions.length === 0 && (
              <tr>
                <td colSpan={7} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>No responder containment logs recorded.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Sub-component: System Health Tab
interface SystemHealthViewProps {
  health: SystemHealth;
}

function SystemHealthView({ health }: SystemHealthViewProps) {
  return (
    <div className="cyber-panel animate-slide-in" style={{ padding: '24px' }}>
      <h3 style={{ margin: '0 0 24px 0', fontSize: '15px', color: 'var(--accent-cyan)' }}>Security Modules Health Status</h3>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px' }}>
        <div className="cyber-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>Telemetry Mode</div>
            <div style={{ fontSize: '16px', fontWeight: '800', marginTop: '6px' }}>{health.telemetry_mode}</div>
          </div>
          <span className="indicator-dot active" />
        </div>

        <div className="cyber-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>Windows Collector</div>
            <div style={{ fontSize: '16px', fontWeight: '800', marginTop: '6px' }}>{health.windows_collector}</div>
          </div>
          <span className={`indicator-dot ${health.windows_collector === 'RUNNING' ? 'active' : health.windows_collector === 'DEGRADED' ? 'warning' : 'inactive'}`} />
        </div>

        <div className="cyber-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>Rules Core Engine</div>
            <div style={{ fontSize: '16px', fontWeight: '800', marginTop: '6px' }}>{health.detection}</div>
          </div>
          <span className={`indicator-dot ${health.detection === 'RUNNING' ? 'active' : 'inactive'}`} />
        </div>

        <div className="cyber-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>Correlation Core Engine</div>
            <div style={{ fontSize: '16px', fontWeight: '800', marginTop: '6px' }}>{health.correlation}</div>
          </div>
          <span className={`indicator-dot ${health.correlation === 'RUNNING' ? 'active' : 'inactive'}`} />
        </div>

        <div className="cyber-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>SQLite Database</div>
            <div style={{ fontSize: '16px', fontWeight: '800', marginTop: '6px' }}>{health.database}</div>
          </div>
          <span className={`indicator-dot ${health.database === 'CONNECTED' ? 'active' : 'inactive'}`} />
        </div>

        <div className="cyber-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 'bold' }}>Auto-Response Policy</div>
            <div style={{ fontSize: '16px', fontWeight: '800', marginTop: '6px' }}>{health.response_mode}</div>
          </div>
          <span className="indicator-dot active" />
        </div>
      </div>

      {health.warnings.length > 0 && (
        <div style={{ marginTop: '30px', padding: '20px', backgroundColor: 'rgba(245,158,11,0.03)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: '6px' }}>
          <h4 style={{ margin: '0 0 10px 0', color: 'var(--accent-orange)', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
            ⚠️ Active System Warnings
          </h4>
          <ul style={{ margin: '0', paddingLeft: '20px', fontSize: '12px', lineHeight: '1.6', color: 'var(--text-secondary)' }}>
            {health.warnings.map((warn, i) => (
              <li key={i}>{warn}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// Helpers
function getRiskColor(score: number): string {
  if (score <= 30) return 'var(--accent-green)';
  if (score <= 50) return 'var(--accent-orange)';
  if (score <= 70) return '#f97316';
  if (score <= 85) return 'var(--accent-red)';
  return '#be123c';
}
