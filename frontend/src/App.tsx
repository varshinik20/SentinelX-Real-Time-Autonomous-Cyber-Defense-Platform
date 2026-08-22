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
          <div className="sidebar-logo">SENTINELX</div>
          <span className={`indicator-dot ${wsStatus === 'connected' ? 'active' : 'inactive'}`} />
        </div>
        
        <div className="sidebar-menu">
          <div className={`menu-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
            Command Center
          </div>
          <div className={`menu-item ${activeTab === 'events' ? 'active' : ''}`} onClick={() => setActiveTab('events')}>
            Live Event Feed
          </div>
          <div className={`menu-item ${activeTab === 'incidents' ? 'active' : ''}`} onClick={() => { setActiveTab('incidents'); setSelectedIncidentId(null); }}>
            Incidents ({activeIncidents.length})
          </div>
          <div className={`menu-item ${activeTab === 'audit' ? 'active' : ''}`} onClick={() => setActiveTab('audit')}>
            Response Audit
          </div>
          <div className={`menu-item ${activeTab === 'health' ? 'active' : ''}`} onClick={() => setActiveTab('health')}>
            System Health
          </div>
        </div>

        <div className="sidebar-footer">
          <div>Status: <span className="mono-text">{wsStatus.toUpperCase()}</span></div>
          <div style={{ marginTop: '4px' }}>Mode: <span className="mono-text">{health.telemetry_mode}</span></div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="main-content">
        <div className="header">
          <div className="header-title">
            {activeTab === 'dashboard' && 'Security Operations Command Center'}
            {activeTab === 'events' && 'Real-Time Endpoint & Network Telemetry'}
            {activeTab === 'incidents' && (selectedIncidentId ? 'Incident Detailed Investigation' : 'Security Incident Lifecycle Manager')}
            {activeTab === 'audit' && 'Simulated Response Actions Audit'}
            {activeTab === 'health' && 'SentinelX Agent & Module Health'}
          </div>
          <div style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
            System state: {health.degraded ? <span style={{ color: 'var(--accent-orange)' }}>DEGRADED</span> : <span style={{ color: 'var(--accent-green)' }}>PROTECTED</span>}
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
        <div className="metric-card glass-panel">
          <div className="metric-header">Telemetry Rate</div>
          <div className="metric-value">{events.length > 0 ? (events.length / 60).toFixed(1) : 0} <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>eps</span></div>
        </div>
        <div className="metric-card glass-panel">
          <div className="metric-header">Active Threats</div>
          <div className="metric-value" style={{ color: activeIncidents.length > 0 ? 'var(--accent-red)' : 'var(--text-primary)' }}>
            {activeIncidents.length}
          </div>
        </div>
        <div className="metric-card glass-panel">
          <div className="metric-header">Maximum Risk</div>
          <div className="metric-value" style={{ color: maxRiskIncident ? getRiskColor(maxRiskIncident.risk_score) : 'var(--text-primary)' }}>
            {maxRiskIncident ? maxRiskIncident.risk_score : 0}<span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>/100</span>
          </div>
        </div>
        <div className="metric-card glass-panel">
          <div className="metric-header">Active Users</div>
          <div className="metric-value">{uniqueUsers}</div>
        </div>
        <div className="metric-card glass-panel">
          <div className="metric-header">Monitored Assets</div>
          <div className="metric-value">{uniqueHosts} <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>hosts</span></div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '30px', marginTop: '30px' }}>
        {/* Active Incident List */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ margin: '0 0 20px 0', fontSize: '18px' }}>Critical Active Incidents</h3>
          <div className="table-container">
            {activeIncidents.length === 0 ? (
              <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>No active incidents detected. Laboratory environment is quiet.</div>
            ) : (
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Host</th>
                    <th>User</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {activeIncidents.slice(0, 5).map((inc) => (
                    <tr key={inc.incident_id}>
                      <td>
                        <span className={`badge badge-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                      </td>
                      <td style={{ fontWeight: '700', fontFamily: 'JetBrains Mono', color: getRiskColor(inc.risk_score) }}>{inc.risk_score}</td>
                      <td>{inc.host}</td>
                      <td>{inc.user || '-'}</td>
                      <td>
                        <button 
                          style={{ background: 'transparent', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer' }}
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
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', height: '400px' }}>
          <h3 style={{ margin: '0 0 20px 0', fontSize: '18px' }}>Security Events Stream</h3>
          <div className="mono-text" style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.4)', borderRadius: '8px', padding: '16px', overflowY: 'auto', fontSize: '12px', color: '#10b981', display: 'flex', flexDirection: 'column-reverse' }}>
            {events.slice(0, 100).map((e) => (
              <div key={e.event_id} style={{ marginBottom: '6px', lineBreak: 'anywhere' }}>
                <span style={{ color: '#6b7280' }}>[{new Date(e.timestamp).toLocaleTimeString()}]</span>{' '}
                <span style={{ color: e.severity === 'HIGH' || e.severity === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>
                  {e.event_type}
                </span>{' '}
                - {e.message}
              </div>
            ))}
            {events.length === 0 && <div style={{ color: 'var(--text-muted)' }}>Waiting for incoming telemetry events...</div>}
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
    <div className="glass-panel animate-slide-in" style={{ padding: '24px' }}>
      {/* Filters Row */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '24px', flexWrap: 'wrap' }}>
        <input 
          type="text" 
          placeholder="Search host, user, message..." 
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{ flex: 1, minWidth: '200px', backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px 16px', color: 'var(--text-primary)', outline: 'none' }}
        />
        <select 
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px 16px', color: 'var(--text-primary)', outline: 'none' }}
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
          style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px 16px', color: 'var(--text-primary)', outline: 'none' }}
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
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((e) => (
              <tr key={e.event_id}>
                <td className="mono-text" style={{ fontSize: '12px' }}>{new Date(e.timestamp).toLocaleString()}</td>
                <td><span style={{ color: 'var(--accent-cyan)' }}>{e.event_type}</span></td>
                <td>
                  <span className={`badge badge-${e.severity.toLowerCase()}`}>{e.severity}</span>
                </td>
                <td>{e.host}</td>
                <td>{e.user || '-'}</td>
                <td style={{ fontSize: '13px', maxWidth: '300px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{e.message}</td>
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
    <div style={{ display: 'grid', gridTemplateColumns: selectedIncidentId ? '350px 1fr' : '1fr', gap: '30px' }} className="animate-slide-in">
      {/* Sidebar List */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 style={{ margin: '0 0 10px 0', fontSize: '18px' }}>Security Incidents</h3>
        {incidents.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', padding: '20px 0' }}>No incidents matched.</div>
        ) : (
          incidents.map((inc) => (
            <div 
              key={inc.incident_id}
              className="glass-panel"
              onClick={() => setSelectedIncidentId(inc.incident_id)}
              style={{
                padding: '16px',
                cursor: 'pointer',
                borderLeft: `4px solid ${getRiskColor(inc.risk_score)}`,
                backgroundColor: selectedIncidentId === inc.incident_id ? 'rgba(255,255,255,0.02)' : 'transparent',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span className="mono-text" style={{ fontSize: '12px', fontWeight: 'bold' }}>{inc.incident_id.slice(0, 8)}</span>
                <span className={`badge badge-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
              </div>
              <div style={{ fontSize: '14px', fontWeight: '600' }}>Host: {inc.host}</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <span>Risk: <b style={{ color: getRiskColor(inc.risk_score) }}>{inc.risk_score}</b></span>
                <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Incident Detail Investigation View */}
      {selectedIncidentId && selectedIncident ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Card: Header Details */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div>
                <span className="mono-text" style={{ color: 'var(--text-muted)' }}>Incident UUID: {selectedIncident.incident_id}</span>
                <h2 style={{ margin: '6px 0 0 0' }}>Host Compromise on {selectedIncident.host}</h2>
              </div>
              <div className="risk-dial-container">
                <svg width="120" height="120">
                  <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
                  <circle 
                    cx="60" 
                    cy="60" 
                    r="50" 
                    fill="none" 
                    stroke={getRiskColor(selectedIncident.risk_score)} 
                    strokeWidth="8" 
                    strokeDasharray="314.16"
                    strokeDashoffset={314.16 - (314.16 * selectedIncident.risk_score) / 100}
                    transform="rotate(-90 60 60)"
                  />
                </svg>
                <div className="risk-dial-label" style={{ color: getRiskColor(selectedIncident.risk_score) }}>
                  {selectedIncident.risk_score}
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>SEVERITY</div>
                <div style={{ fontWeight: '700', marginTop: '4px' }}>
                  <span className={`badge badge-${selectedIncident.severity.toLowerCase()}`}>{selectedIncident.severity}</span>
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>STATUS</div>
                <div style={{ fontWeight: '700', marginTop: '4px', color: 'var(--accent-cyan)' }}>{selectedIncident.status}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>TARGET USER</div>
                <div style={{ fontWeight: '700', marginTop: '4px' }}>{selectedIncident.user || 'Unknown'}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>SOURCE IPS</div>
                <div style={{ fontWeight: '700', marginTop: '4px' }}>{selectedIncident.source_ips.join(', ') || '127.0.0.1'}</div>
              </div>
            </div>
          </div>

          {/* Interactive SVG Attack Graph */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 16px 0' }}>Reconstructed Attack Graph</h3>
            <AttackGraphRenderer graph={selectedIncident.attack_graph} />
          </div>

          {/* Card: AI Investigation & Recommendations */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '24px' }}>
            <div className="glass-panel" style={{ padding: '24px', borderLeft: '4px solid var(--accent-purple)' }}>
              <h3 style={{ margin: '0 0 12px 0', color: 'var(--accent-purple)' }}>🤖 AI Copilot Analysis</h3>
              <p style={{ fontSize: '14px', lineHeight: '1.6', margin: '0' }}>{selectedIncident.ai_summary || 'Analyzing evidence...'}</p>
            </div>
            
            <div className="glass-panel" style={{ padding: '24px' }}>
              <h3 style={{ margin: '0 0 12px 0', color: 'var(--accent-green)' }}>🛡️ Recommended Containment Playbook</h3>
              <ul style={{ paddingLeft: '20px', margin: '0', fontSize: '13px', lineHeight: '1.7' }}>
                {selectedIncident.recommendations.map((rec, index) => (
                  <li key={index} style={{ marginBottom: '8px' }}>{rec}</li>
                ))}
                {selectedIncident.recommendations.length === 0 && <li>Analyzing threat layout...</li>}
              </ul>
            </div>
          </div>

          {/* Card: MITRE ATT&CK Mappings */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 16px 0' }}>MITRE ATT&CK Techniques Mapped</h3>
            <div className="table-container">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Technique ID</th>
                    <th>Technique Name</th>
                    <th>Tactic</th>
                    <th>Confidence</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedIncident.attack_techniques.map((tech, index) => (
                    <tr key={index}>
                      <td className="mono-text" style={{ color: 'var(--accent-cyan)' }}>{tech.technique_id}</td>
                      <td><b>{tech.technique_name}</b></td>
                      <td>{tech.tactic}</td>
                      <td>{(tech.confidence * 100).toFixed(0)}%</td>
                      <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{tech.evidence}</td>
                    </tr>
                  ))}
                  {selectedIncident.attack_techniques.length === 0 && (
                    <tr>
                      <td colSpan={5} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-secondary)' }}>No techniques mapped.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Card: Chronological Timeline */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 20px 0' }}>Incident Event Timeline</h3>
            <div className="timeline">
              {selectedIncident.related_alerts.map((al) => (
                <div key={al.alert_id} className="timeline-item" style={{ marginBottom: '10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                    <span style={{ fontWeight: '700', color: 'var(--accent-orange)' }}>Alert Triggered: {al.rule_name}</span>
                    <span className="mono-text" style={{ color: 'var(--text-muted)' }}>{new Date(al.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>{al.message}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '80px', textAlign: 'center', color: 'var(--text-secondary)' }}>
          Select an incident from the side pane to launch active security investigation.
        </div>
      )}
    </div>
  );
}

// Sub-component: Attack Graph Renderer (SVG Node-Link diagram)
interface AttackGraphRendererProps {
  graph: AttackGraph;
}

function AttackGraphRenderer({ graph }: AttackGraphRendererProps) {
  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return <div style={{ height: '350px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>No attack graph available for this event layout.</div>;
  }

  const width = 800;
  const height = 450;

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
    const x = 70 + lNum * 220; // x-position of layer
    list.forEach((node, idx) => {
      const y = (idx + 1) * (height / (n_nodes + 1));
      nodeCoords[node.id] = { x, y };
    });
  });

  // Color mapper helper
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
      <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} style={{ background: '#090d16' }}>
        {/* SVG Marker Definition for Directed Edge Arrows */}
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.2)" />
          </marker>
        </defs>

        {/* Draw Edges */}
        {graph.edges.map((edge, idx) => {
          const from = nodeCoords[edge.source];
          const to = nodeCoords[edge.target];
          if (!from || !to) return null;
          return (
            <g key={`edge-${idx}`}>
              <line 
                x1={from.x} y1={from.y} 
                x2={to.x} y2={to.y} 
                stroke="rgba(255,255,255,0.12)" 
                strokeWidth="2" 
                markerEnd="url(#arrow)" 
              />
              <text 
                x={(from.x + to.x) / 2} 
                y={(from.y + to.y) / 2 - 4} 
                fill="var(--text-muted)" 
                fontSize="9" 
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
                r="12" 
                fill="#111827" 
                stroke={color} 
                strokeWidth="2.5" 
                style={{ filter: `drop-shadow(0px 0px 4px ${color})` }} 
              />
              <text 
                y="-18" 
                fill="var(--text-primary)" 
                fontSize="11" 
                fontWeight="bold"
                textAnchor="middle"
              >
                {node.label.length > 20 ? node.label.slice(0, 17) + '...' : node.label}
              </text>
              <text 
                y="26" 
                fill="var(--text-muted)" 
                fontSize="9" 
                textAnchor="middle"
                className="mono-text"
              >
                {node.type.toUpperCase()}
              </text>
            </g>
          );
        })}
      </svg>
      {/* Legend overlay */}
      <div style={{ position: 'absolute', bottom: '16px', left: '16px', display: 'flex', gap: '12px', fontSize: '10px' }} className="mono-text">
        <span style={{ color: 'var(--accent-purple)' }}>● IP</span>
        <span style={{ color: 'var(--accent-green)' }}>● User</span>
        <span style={{ color: 'var(--accent-cyan)' }}>● Host</span>
        <span style={{ color: 'var(--accent-orange)' }}>● Process</span>
        <span style={{ color: 'var(--accent-red)' }}>● Alert</span>
      </div>
    </div>
  );
}

// Sub-component: Response Audit Tab
interface ResponseAuditViewProps {
  actions: ResponseAction[];
}

function ResponseAuditView({ actions }: ResponseAuditViewProps) {
  return (
    <div className="glass-panel animate-slide-in" style={{ padding: '24px' }}>
      <h3 style={{ margin: '0 0 16px 0' }}>Simulated Mitigation Logs</h3>
      <div className="table-container">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action ID</th>
              <th>Action Type</th>
              <th>Target Entity</th>
              <th>Reason</th>
              <th>Engine Mode</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((act) => (
              <tr key={act.action_id}>
                <td className="mono-text" style={{ fontSize: '12px' }}>{new Date(act.timestamp).toLocaleString()}</td>
                <td className="mono-text" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{act.action_id.slice(0, 8)}</td>
                <td><span style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>{act.action_type}</span></td>
                <td><span className="mono-text">{act.target}</span></td>
                <td style={{ fontSize: '13px' }}>{act.reason}</td>
                <td>
                  <span style={{ padding: '2px 6px', backgroundColor: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '10px' }}>
                    {act.mode}
                  </span>
                </td>
                <td>
                  <span style={{ color: 'var(--accent-green)', fontWeight: 'bold', fontSize: '12px' }}>
                    {act.status}
                  </span>
                </td>
              </tr>
            ))}
            {actions.length === 0 && (
              <tr>
                <td colSpan={7} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>No mitigations logged.</td>
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
    <div className="glass-panel animate-slide-in" style={{ padding: '24px' }}>
      <h3 style={{ margin: '0 0 24px 0' }}>Service Status Matrix</h3>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Telemetry Mode</div>
            <div style={{ fontSize: '18px', fontWeight: '700', marginTop: '6px' }}>{health.telemetry_mode}</div>
          </div>
          <span className="indicator-dot active" />
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Windows Collector</div>
            <div style={{ fontSize: '18px', fontWeight: '700', marginTop: '6px' }}>{health.windows_collector}</div>
          </div>
          <span className={`indicator-dot ${health.windows_collector === 'RUNNING' ? 'active' : health.windows_collector === 'DEGRADED' ? 'warning' : 'inactive'}`} />
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Detection Engine</div>
            <div style={{ fontSize: '18px', fontWeight: '700', marginTop: '6px' }}>{health.detection}</div>
          </div>
          <span className={`indicator-dot ${health.detection === 'RUNNING' ? 'active' : 'inactive'}`} />
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Correlation Engine</div>
            <div style={{ fontSize: '18px', fontWeight: '700', marginTop: '6px' }}>{health.correlation}</div>
          </div>
          <span className={`indicator-dot ${health.correlation === 'RUNNING' ? 'active' : 'inactive'}`} />
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>SQL Database</div>
            <div style={{ fontSize: '18px', fontWeight: '700', marginTop: '6px' }}>{health.database}</div>
          </div>
          <span className={`indicator-dot ${health.database === 'CONNECTED' ? 'active' : 'inactive'}`} />
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Response Mode</div>
            <div style={{ fontSize: '18px', fontWeight: '700', marginTop: '6px' }}>{health.response_mode}</div>
          </div>
          <span className="indicator-dot active" />
        </div>
      </div>

      {health.warnings.length > 0 && (
        <div style={{ marginTop: '30px', padding: '20px', backgroundColor: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: '8px' }}>
          <h4 style={{ margin: '0 0 10px 0', color: 'var(--accent-orange)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            ⚠️ Active System Warnings
          </h4>
          <ul style={{ margin: '0', paddingLeft: '20px', fontSize: '13px', lineHeight: '1.6' }}>
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
