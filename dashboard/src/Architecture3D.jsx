import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';

const ARCHITECTURE_NODES = [
  // LAYER 1: Client Edge & Multi-Path (Y = 6)
  {
    id: 'client_edge',
    name: 'Quantum-Safe Mobile/Desktop Client',
    layer: 'Layer 1: Client Edge & Multi-Path',
    layerIndex: 0,
    position: [-4, 6, 0],
    color: 0x38bdf8, // Cyan
    specs: {
      'Protocol': 'mPQC Quantum-Safe Handshake',
      'Mutual Auth': 'NIST FIPS 204 (ML-DSA-65)',
      'Key Exchange': 'ML-KEM-768 + X25519 Hybrid',
      'Target Platform': 'POSIX Linux, WSL2, macOS, Windows',
      'Source File': 'src/client/hybrid_par_client.c'
    },
    description: 'Executes parallel dual-threaded classical X25519 and PQC ML-KEM-768 key exchange to negotiate zero-trust tunnels.'
  },
  {
    id: 'multipath',
    name: 'AEAD Multi-Path Bonding Pool',
    layer: 'Layer 1: Client Edge & Multi-Path',
    layerIndex: 0,
    position: [4, 6, 0],
    color: 0x0ea5e9, // Darker Cyan
    specs: {
      'Algorithm': 'Round-Robin AEAD Frame Multiplexing',
      'Interfaces': 'eth0, wlan0, 5G Multi-homing',
      'Failover': '< 10ms Zero-Loss Failover',
      'Source File': 'src/common/multipath.c'
    },
    description: 'Spreads AEAD-encrypted payloads across multiple physical network interfaces for maximum bandwidth and fault tolerance.'
  },

  // LAYER 2: Kernel & Acceleration (Y = 3)
  {
    id: 'tun_driver',
    name: 'Linux Virtual TUN Driver (/dev/net/tun)',
    layer: 'Layer 2: Kernel Acceleration & Routing',
    layerIndex: 1,
    position: [-4, 3, 0],
    color: 0x10b981, // Emerald
    specs: {
      'Device Path': '/dev/net/tun (tun0 / tun1)',
      'Mode': 'IFF_TUN | IFF_NO_PI (Layer 3 IP Packets)',
      'Queue Depth': '1024 Network Packets',
      'Source File': 'src/common/tun.c'
    },
    description: 'Virtual network driver creating secure IP tunnel interfaces directly in the Linux kernel network stack.'
  },
  {
    id: 'ebpf_xdp',
    name: 'eBPF / XDP Line-Rate Packet Accelerator',
    layer: 'Layer 2: Kernel Acceleration & Routing',
    layerIndex: 1,
    position: [4, 3, 0],
    color: 0x34d399, // Mint Emerald
    specs: {
      'Hook Type': 'XDP (eXpress Data Path) Bare-Metal',
      'Action': 'XDP_REDIRECT / XDP_PASS',
      'Bypass Latency': '< 1.2 microseconds',
      'Source File': 'src/common/ebpf_xdp.c'
    },
    description: 'Executes bytecode inside Linux network drivers before SKB memory allocation for 100Gbps line-rate filtering.'
  },

  // LAYER 3: PQC Hybrid Crypto Engine (Y = 0)
  {
    id: 'ml_kem',
    name: 'NIST FIPS 203: ML-KEM-768 (Kyber)',
    layer: 'Layer 3: PQC Hybrid Cryptographic Engine',
    layerIndex: 2,
    position: [-5, 0, 0],
    color: 0xa855f7, // Purple
    specs: {
      'Standard': 'NIST FIPS 203 (Post-Quantum KEM)',
      'Security Level': 'Category 3 (AES-192 Equivalent)',
      'Public Key Size': '1,184 Bytes',
      'Ciphertext Size': '1,088 Bytes',
      'Execution': 'Concurrent pthread Parallel Execution'
    },
    description: 'Post-quantum key encapsulation mechanism resistant to Shor Algorithm attacks on quantum computers.'
  },
  {
    id: 'ml_dsa',
    name: 'NIST FIPS 204: ML-DSA-65 (Dilithium)',
    layer: 'Layer 3: PQC Hybrid Cryptographic Engine',
    layerIndex: 2,
    position: [0, 0, 0],
    color: 0xc084fc, // Lavender Purple
    specs: {
      'Standard': 'NIST FIPS 204 (Post-Quantum Signature)',
      'Security Level': 'Category 3 Quantum Signature',
      'Public Key Size': '1,952 Bytes',
      'Signature Size': '3,309 Bytes',
      'Authentication': 'Mutual PQC Identity Verification'
    },
    description: 'Quantum-resistant lattice-based digital signatures ensuring unforgeable node authentication.'
  },
  {
    id: 'crypto_hybrid',
    name: 'Hybrid KDF & AES-256-GCM Engine',
    layer: 'Layer 3: PQC Hybrid Cryptographic Engine',
    layerIndex: 2,
    position: [5, 0, 0],
    color: 0x8b5cf6, // Violet
    specs: {
      'Classical Exchange': 'X25519 Ephemeral ECDH',
      'KDF Standard': 'HKDF-SHA256 (RFC 5869)',
      'Symmetric AEAD': 'AES-256-GCM (NIST SP 800-38D)',
      'Latency Cap': 'max(T_classical, T_pqc)',
      'Source File': 'src/common/hybrid_kdf.c, aead.c'
    },
    description: 'Combines classical X25519 + PQC ML-KEM-768 into a single 256-bit symmetric session key with hardware AES-NI acceleration.'
  },

  // LAYER 4: Zero-Trust & Defensive Engine (Y = -3)
  {
    id: 'dpi_camouflage',
    name: 'DPI Pseudorandom Traffic Camouflage',
    layer: 'Layer 4: Defensive & Zero-Trust Access',
    layerIndex: 3,
    position: [-5, -3, 0],
    color: 0xf59e0b, // Amber
    specs: {
      'Padding Dynamic Range': '16 to 128 Bytes Dynamic PRNG',
      'Target Mitigations': 'Deep Packet Inspection / Fingerprinting',
      'Entropy Masking': 'Cryptographic PRNG Overhead Padding',
      'Source File': 'src/common/framing.c'
    },
    description: 'Masks exact VPN payload length distributions to defeat AI-driven network traffic classification.'
  },
  {
    id: 'ztna_engine',
    name: 'Zero-Trust (ZTNA) L7 Micro-Segmentation',
    layer: 'Layer 4: Defensive & Zero-Trust Access',
    layerIndex: 3,
    position: [0, -3, 0],
    color: 0xd97706, // Dark Amber
    specs: {
      'Policy Engine': 'Identity-Based L7 IP/Port Access Rules',
      'Default Action': 'Strict Implicit Deny All',
      'Anti-Replay': 'IPsec RFC 6479 64-Packet Bitmask Window',
      'Source File': 'src/common/ztna.c'
    },
    description: 'Enforces identity-scoped access control rules preventing lateral movement across enterprise networks.'
  },
  {
    id: 'anti_downgrade',
    name: 'Signed Anti-Downgrade Security Lock',
    layer: 'Layer 4: Defensive & Zero-Trust Access',
    layerIndex: 3,
    position: [5, -3, 0],
    color: 0xfbbf24, // Light Amber
    specs: {
      'Policy Flag': 'PQC_POLICY_STRICT_PQC Required',
      'Mitigation': 'MitM Quantum Stripping & Downgrade Prevention',
      'Session Resumption': 'Quantum-Safe 0-RTT Session Tickets',
      'Source File': 'src/common/state_machine.c'
    },
    description: 'Binds PQC algorithm requirements to signed handshakes, preventing rogue active attackers from downgrading to weak ciphers.'
  },

  // LAYER 5: Control Plane & Telemetry (Y = -6)
  {
    id: 'telemetry_ipc',
    name: 'Non-Blocking UDP IPC Telemetry Exporter',
    layer: 'Layer 5: Control Plane & Telemetry',
    layerIndex: 4,
    position: [-4, -6, 0],
    color: 0x06b6d4, // Cyan
    specs: {
      'Transport Protocol': 'UDP Socket datagrams (127.0.0.1:9090)',
      'Payload Format': 'JSON Real-Time System Metrics',
      'Non-Blocking': 'Zero Overhead on Core C Data Plane',
      'Source File': 'src/common/telemetry.c'
    },
    description: 'Streams live execution telemetry (microsecond latencies, packet counts, active clients) to management services.'
  },
  {
    id: 'control_api',
    name: 'Node.js Express Management Control API',
    layer: 'Layer 5: Control Plane & Telemetry',
    layerIndex: 4,
    position: [4, -6, 0],
    color: 0x67e8f9, // Light Cyan
    specs: {
      'Backend Runtime': 'Node.js Express + Native dgram UDP Socket',
      'API Endpoints': '/api/status, /api/start, /api/stop, /api/metrics',
      'Daemon Manager': 'Child Process Spawner & Health Monitor',
      'Source File': 'management-api/server.js'
    },
    description: 'Management API interfacing between low-level C daemon process telemetry and web user interfaces.'
  }
];

const LAYER_PLATFORMS = [
  { name: 'Layer 1: Client Edge & Multi-Path Bonding', y: 6, color: 0x0284c7 },
  { name: 'Layer 2: Kernel Network Routing & eBPF/XDP', y: 3, color: 0x059669 },
  { name: 'Layer 3: PQC Hybrid Cryptographic Engine', y: 0, color: 0x7c3aed },
  { name: 'Layer 4: Zero-Trust ZTNA & Defensive Camouflage', y: -3, color: 0xd97706 },
  { name: 'Layer 5: Management Control Plane & UDP Telemetry', y: -6, color: 0x0891b2 }
];

export default function Architecture3D() {
  const mountRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(ARCHITECTURE_NODES[4]); // Default selected ML-KEM
  const [viewPreset, setViewPreset] = useState('isometric');
  const [autoRotate, setAutoRotate] = useState(true);

  const sceneRef = useRef(null);
  const cameraRef = useRef(null);
  const rendererRef = useRef(null);
  const nodesMeshMapRef = useRef(new Map());
  const particlesRef = useRef([]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight;

    // 1. Scene
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x0f172a, 0.035);
    sceneRef.current = scene;

    // 2. Camera
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(18, 12, 22);
    camera.lookAt(0, 0, 0);
    cameraRef.current = camera;

    // 3. Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = true;
    rendererRef.current = renderer;

    container.appendChild(renderer.domElement);

    // 4. Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.9);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x60a5fa, 1.5);
    dirLight.position.set(20, 30, 20);
    scene.add(dirLight);

    const pointLight = new THREE.PointLight(0xa855f7, 2, 50);
    pointLight.position.set(0, 0, 10);
    scene.add(pointLight);

    // 5. Grid Background & Layer Platforms
    const gridHelper = new THREE.GridHelper(30, 30, 0x334155, 0x1e293b);
    gridHelper.position.y = -8;
    scene.add(gridHelper);

    // Render glassmorphic horizontal layer platforms
    LAYER_PLATFORMS.forEach((platform) => {
      const geometry = new THREE.BoxGeometry(16, 0.15, 10);
      const material = new THREE.MeshPhongMaterial({
        color: platform.color,
        transparent: true,
        opacity: 0.15,
        shininess: 100,
        wireframe: false
      });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(0, platform.y - 0.6, 0);
      scene.add(mesh);

      // Layer platform wireframe outline
      const edges = new THREE.EdgesGeometry(geometry);
      const lineMaterial = new THREE.LineBasicMaterial({ color: platform.color, transparent: true, opacity: 0.4 });
      const wireframe = new THREE.LineSegments(edges, lineMaterial);
      wireframe.position.set(0, platform.y - 0.6, 0);
      scene.add(wireframe);
    });

    // 6. Build Interactive 3D Node Meshes
    ARCHITECTURE_NODES.forEach((node) => {
      const group = new THREE.Group();
      group.position.set(...node.position);

      // Glass Box geometry for node
      const geometry = new THREE.BoxGeometry(2.8, 1.2, 2.2);
      const material = new THREE.MeshPhongMaterial({
        color: node.color,
        transparent: true,
        opacity: 0.85,
        shininess: 90
      });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.userData = node;
      group.add(mesh);

      // Wireframe glow highlight
      const edges = new THREE.EdgesGeometry(geometry);
      const lineMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.6 });
      const wireframe = new THREE.LineSegments(edges, lineMat);
      group.add(wireframe);

      scene.add(group);
      nodesMeshMapRef.current.set(node.id, group);
    });

    // 7. Animated Laser Beams & Particles connecting layers
    const connections = [
      [ARCHITECTURE_NODES[0], ARCHITECTURE_NODES[2]], // Client -> TUN
      [ARCHITECTURE_NODES[1], ARCHITECTURE_NODES[3]], // MultiPath -> eBPF XDP
      [ARCHITECTURE_NODES[2], ARCHITECTURE_NODES[4]], // TUN -> ML-KEM
      [ARCHITECTURE_NODES[3], ARCHITECTURE_NODES[6]], // eBPF -> Hybrid Crypto
      [ARCHITECTURE_NODES[4], ARCHITECTURE_NODES[7]], // ML-KEM -> DPI Camouflage
      [ARCHITECTURE_NODES[5], ARCHITECTURE_NODES[8]], // ML-DSA -> ZTNA Engine
      [ARCHITECTURE_NODES[6], ARCHITECTURE_NODES[9]], // Hybrid Crypto -> Anti-Downgrade
      [ARCHITECTURE_NODES[7], ARCHITECTURE_NODES[10]], // DPI -> Telemetry UDP
      [ARCHITECTURE_NODES[8], ARCHITECTURE_NODES[11]]  // ZTNA -> Control API
    ];

    const particlesArray = [];
    connections.forEach(([n1, n2]) => {
      const p1 = new THREE.Vector3(...n1.position);
      const p2 = new THREE.Vector3(...n2.position);

      // Line laser
      const points = [p1, p2];
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
      const lineMat = new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.35 });
      const line = new THREE.Line(lineGeo, lineMat);
      scene.add(line);

      // Flowing particle
      const pGeo = new THREE.SphereGeometry(0.18, 8, 8);
      const pMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8 });
      const pMesh = new THREE.Mesh(pGeo, pMat);
      scene.add(pMesh);

      particlesArray.push({
        mesh: pMesh,
        start: p1,
        end: p2,
        progress: Math.random()
      });
    });
    particlesRef.current = particlesArray;

    // 8. Raycaster Mouse Interaction
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handlePointerDown = (event) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(scene.children, true);

      for (let i = 0; i < intersects.length; i++) {
        const obj = intersects[i].object;
        if (obj.userData && obj.userData.id) {
          setSelectedNode(obj.userData);
          break;
        }
      }
    };

    const canvasEl = renderer.domElement;
    canvasEl.addEventListener('pointerdown', handlePointerDown);

    // 9. Simple Orbit Rotation Animation Loop
    let angle = 0;
    let animId;

    const animate = () => {
      animId = requestAnimationFrame(animate);

      // Move glowing particles along connections
      particlesRef.current.forEach((p) => {
        p.progress += 0.012;
        if (p.progress > 1) p.progress = 0;
        p.mesh.position.lerpVectors(p.start, p.end, p.progress);
      });

      // Auto rotation
      if (autoRotate && viewPreset === 'isometric') {
        angle += 0.003;
        camera.position.x = 22 * Math.cos(angle);
        camera.position.z = 22 * Math.sin(angle);
        camera.lookAt(0, 0, 0);
      }

      renderer.render(scene, camera);
    };
    animate();

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      canvasEl.removeEventListener('pointerdown', handlePointerDown);
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [autoRotate, viewPreset]);

  // Handle Preset Camera Views
  const applyViewPreset = (preset) => {
    setViewPreset(preset);
    const camera = cameraRef.current;
    if (!camera) return;

    if (preset === 'isometric') {
      camera.position.set(18, 12, 22);
      camera.lookAt(0, 0, 0);
    } else if (preset === 'top') {
      camera.position.set(0, 26, 0.1);
      camera.lookAt(0, 0, 0);
    } else if (preset === 'crypto') {
      camera.position.set(0, 2, 14);
      camera.lookAt(0, 0, 0);
    } else if (preset === 'stack') {
      camera.position.set(22, 0, 0);
      camera.lookAt(0, 0, 0);
    }
  };

  return (
    <div style={{ position: 'relative', width: '100%', height: '650px', backgroundColor: '#0b1120', borderRadius: '1rem', border: '1px solid #334155', overflow: 'hidden' }}>
      
      {/* 3D Viewport Controls Bar */}
      <div style={{ position: 'absolute', top: '1rem', left: '1rem', zIndex: 10, display: 'flex', gap: '0.5rem', backgroundColor: 'rgba(15, 23, 42, 0.85)', backdropFilter: 'blur(8px)', padding: '0.5rem', borderRadius: '0.75rem', border: '1px solid #334155' }}>
        <button 
          onClick={() => applyViewPreset('isometric')} 
          style={{ padding: '0.4rem 0.8rem', borderRadius: '0.5rem', border: 'none', background: viewPreset === 'isometric' ? '#3b82f6' : '#1e293b', color: '#fff', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 600 }}>
          🌐 3D Isometric
        </button>
        <button 
          onClick={() => applyViewPreset('stack')} 
          style={{ padding: '0.4rem 0.8rem', borderRadius: '0.5rem', border: 'none', background: viewPreset === 'stack' ? '#3b82f6' : '#1e293b', color: '#fff', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 600 }}>
          🥞 Layer Stack
        </button>
        <button 
          onClick={() => applyViewPreset('crypto')} 
          style={{ padding: '0.4rem 0.8rem', borderRadius: '0.5rem', border: 'none', background: viewPreset === 'crypto' ? '#3b82f6' : '#1e293b', color: '#fff', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 600 }}>
          🔐 PQC Crypto View
        </button>
        <button 
          onClick={() => applyViewPreset('top')} 
          style={{ padding: '0.4rem 0.8rem', borderRadius: '0.5rem', border: 'none', background: viewPreset === 'top' ? '#3b82f6' : '#1e293b', color: '#fff', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 600 }}>
          🗺️ Top-Down
        </button>
        <button 
          onClick={() => setAutoRotate(!autoRotate)} 
          style={{ padding: '0.4rem 0.8rem', borderRadius: '0.5rem', border: 'none', background: autoRotate ? '#10b981' : '#334155', color: '#fff', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 600 }}>
          {autoRotate ? '⏸️ Pause Orbit' : '▶️ Auto-Rotate'}
        </button>
      </div>

      {/* WebGL Canvas Container */}
      <div ref={mountRef} style={{ width: '100%', height: '100%', cursor: 'grab' }} />

      {/* Floating 3D Node Inspector Card */}
      {selectedNode && (
        <div style={{
          position: 'absolute',
          bottom: '1rem',
          right: '1rem',
          width: '360px',
          backgroundColor: 'rgba(15, 23, 42, 0.92)',
          backdropFilter: 'blur(12px)',
          borderRadius: '1rem',
          border: `1px solid #${selectedNode.color.toString(16).padStart(6, '0')}`,
          padding: '1.25rem',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
          zIndex: 10,
          color: '#f8fafc'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: `#${selectedNode.color.toString(16).padStart(6, '0')}` }}>
              {selectedNode.layer}
            </span>
            <button 
              onClick={() => setSelectedNode(null)} 
              style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '1rem', cursor: 'pointer' }}>
              ✕
            </button>
          </div>
          <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1.1rem', color: '#fff' }}>{selectedNode.name}</h3>
          <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem', color: '#cbd5e1', lineHeight: '1.4' }}>{selectedNode.description}</p>
          
          <div style={{ borderTop: '1px solid #334155', paddingTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            {Object.entries(selectedNode.specs).map(([key, val]) => (
              <div key={key} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
                <span style={{ color: '#94a3b8', fontWeight: 500 }}>{key}:</span>
                <span style={{ color: '#60a5fa', fontWeight: 600, fontFamily: 'monospace' }}>{val}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
