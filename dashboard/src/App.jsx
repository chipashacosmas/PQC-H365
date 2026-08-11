import { useState, useEffect, useRef } from 'react';
import './index.css';
import MetricsChart from './MetricsChart';
import Architecture3D from './Architecture3D';

function App() {
  const [activeTab, setActiveTab] = useState('3d'); // '3d' or 'metrics'
  const [isRunning, setIsRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState([]);
  const [pid, setPid] = useState(null);
  const logsEndRef = useRef(null);

  const API_URL = 'http://localhost:3000/api';

  const checkStatus = async () => {
    try {
      const res = await fetch(`${API_URL}/status`);
      const data = await res.json();
      setIsRunning(data.running);
      setPid(data.pid);
    } catch (e) {
      console.error('API is not reachable');
      setIsRunning(false);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await fetch(`${API_URL}/logs`);
      const data = await res.json();
      setLogs(data);
    } catch (e) {
      console.error('Failed to fetch logs');
    }
  };

  const fetchMetrics = async () => {
    try {
      const res = await fetch(`${API_URL}/metrics`);
      const data = await res.json();
      setMetrics(data);
    } catch (e) {
      console.error('Failed to fetch metrics');
    }
  };

  useEffect(() => {
    checkStatus();
    fetchLogs();
    fetchMetrics();
    const interval = setInterval(() => {
      checkStatus();
      fetchLogs();
      fetchMetrics();
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleStart = async () => {
    try {
      await fetch(`${API_URL}/start`, { method: 'POST' });
      checkStatus();
    } catch (e) {
      console.error('Failed to start');
    }
  };

  const handleStop = async () => {
    try {
      await fetch(`${API_URL}/stop`, { method: 'POST' });
      checkStatus();
    } catch (e) {
      console.error('Failed to stop');
    }
  };

  return (
    <div className="dashboard-container">
      <header className="header">
        <div>
          <h1>PQC Hybrid VPN</h1>
          <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.9rem' }}>
            NIST FIPS 203 (ML-KEM-768) & NIST FIPS 204 (ML-DSA-65) Zero-Trust Control Plane
          </p>
        </div>
        <div className="status-badge">
          <div className={`status-dot ${isRunning ? 'online' : 'offline'}`}></div>
          {isRunning ? `Online (PID: ${pid})` : 'Offline'}
        </div>
      </header>

      <div className="controls" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <button 
            className="btn btn-primary" 
            disabled={isRunning} 
            onClick={handleStart}
          >
            Start Daemon
          </button>
          <button 
            className="btn btn-danger" 
            disabled={!isRunning} 
            onClick={handleStop}
          >
            Stop Daemon
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="tab-nav" style={{ display: 'flex', gap: '0.5rem', backgroundColor: '#0f172a', padding: '0.35rem', borderRadius: '0.75rem', border: '1px solid #334155' }}>
          <button 
            onClick={() => setActiveTab('3d')}
            style={{
              padding: '0.5rem 1.25rem',
              borderRadius: '0.5rem',
              border: 'none',
              backgroundColor: activeTab === '3d' ? '#3b82f6' : 'transparent',
              color: activeTab === '3d' ? '#ffffff' : '#94a3b8',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}>
            🌐 3D Architecture Canvas
          </button>
          <button 
            onClick={() => setActiveTab('metrics')}
            style={{
              padding: '0.5rem 1.25rem',
              borderRadius: '0.5rem',
              border: 'none',
              backgroundColor: activeTab === 'metrics' ? '#3b82f6' : 'transparent',
              color: activeTab === 'metrics' ? '#ffffff' : '#94a3b8',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}>
            📊 Live Metrics & Logs
          </button>
        </div>
      </div>

      {activeTab === '3d' ? (
        <div className="panel" style={{ backgroundColor: '#1e293b', borderRadius: '1rem', border: '1px solid #334155', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ margin: 0, color: '#f8fafc', fontSize: '1.25rem' }}>Interactive 3D System Architecture</h2>
            <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Click 3D nodes to inspect protocol specifications</span>
          </div>
          <Architecture3D />
        </div>
      ) : (
        <div className="main-content" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
          <div className="panel" style={{ backgroundColor: '#1e293b', borderRadius: '1rem', border: '1px solid #334155', padding: '1rem' }}>
            <h2 style={{ marginTop: 0, color: '#f8fafc', fontSize: '1.25rem' }}>Connection Metrics</h2>
            <MetricsChart data={metrics} />
          </div>

          <div className="terminal-window">
            <div className="terminal-header">
              <div className="mac-btn close"></div>
              <div className="mac-btn min"></div>
              <div className="mac-btn max"></div>
            </div>
            <div className="terminal-body">
              {logs.length === 0 ? (
                <div>Awaiting logs...</div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className={`log-line ${log.type === 'error' ? 'log-error' : ''}`}>
                    &gt; {log.text}
                  </div>
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

