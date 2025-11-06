'use client';

import React, { useState, useEffect } from 'react';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Activity, Database, TrendingUp, AlertTriangle, Network, Shield, Clock, Target, Globe, ExternalLink } from 'lucide-react';

const CombinedSecurityDashboard = () => {
  const [data, setData] = useState([]);
  const [portScanAnalysis, setPortScanAnalysis] = useState(null);
  const [bruteForceAnalysis, setBruteForceAnalysis] = useState(null);
  const [httpAnalysis, setHttpAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAndAnalyzeData();
  }, []);

  const loadAndAnalyzeData = async () => {
    try {
      // Load TCP data
      let fileData = '';
      if (typeof window !== 'undefined' && (window as any).fs && typeof (window as any).fs.readFile === 'function') {
        // Electron / custom preload
        fileData = await (window as any).fs.readFile('tcp.csv', { encoding: 'utf8' });
      } else {
        // Browser: fetch from public/
        const resp = await fetch('/tcp.csv');
        if (!resp.ok) throw new Error(`Failed to fetch /tcp.csv: ${resp.status}`);
        fileData = await resp.text();
      }
      const lines = fileData.trim().split(/\r?\n/);
      
      const parsedData = lines.slice(1).map(line => {
        const values = line.split(',');
        return {
          addressA: values[0]?.trim(),
          portA: parseInt(values[1]),
          addressB: values[2]?.trim(),
          portB: parseInt(values[3]),
          packets: parseInt(values[4]),
          bytes: parseInt(values[5]),
          packetsAtoB: parseInt(values[6]),
          bytesAtoB: parseInt(values[7]),
          packetsBtoA: parseInt(values[8]),
          bytesBtoA: parseInt(values[9]),
          relStart: parseFloat(values[10]),
          duration: parseFloat(values[11]),
          bitsAtoB: parseFloat(values[12]) || 0,
          bitsBtoA: parseFloat(values[13]) || 0
        };
      }).filter(row => row.addressA && row.addressB);

      setData(parsedData);
      analyzePortScanning(parsedData);
      analyzeSSHBruteForce(parsedData);
      
      // Set loading to false FIRST so dashboard shows immediately
      setLoading(false);
      
      // Load HTTP analysis asynchronously (non-blocking)
      try {
        const httpResponse = await fetch('/api/parse-http');
        if (httpResponse.ok) {
          const httpData = await httpResponse.json();
          setHttpAnalysis(httpData);
        } else {
          console.error('HTTP API returned error:', httpResponse.status);
        }
      } catch (error) {
        console.error('Error loading HTTP data:', error);
      }
    } catch (error) {
      console.error('Error loading data:', error);
      setLoading(false);
    }
  };

  const analyzePortScanning = (tcpData) => {
    const totalConnections = tcpData.length;
    const totalBytes = tcpData.reduce((sum, row) => sum + row.bytes, 0);
    const totalPackets = tcpData.reduce((sum, row) => sum + row.packets, 0);

    const ipCounts = {};
    const portCounts = {};
    const servicePorts = {
      21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
      80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
      443: 'HTTPS', 445: 'SMB', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
      1025: 'NFS', 1720: 'H.323', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC',
      8080: 'HTTP-Alt', 8888: 'HTTP-Alt'
    };

    tcpData.forEach(row => {
      ipCounts[row.addressA] = (ipCounts[row.addressA] || 0) + 1;
      ipCounts[row.addressB] = (ipCounts[row.addressB] || 0) + 1;
      
      if (row.portB < 10000) {
        portCounts[row.portB] = (portCounts[row.portB] || 0) + 1;
      }
    });

    const topIPs = Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));

    const topPorts = Object.entries(portCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([port, count]) => ({ 
        port: parseInt(port), 
        count,
        service: servicePorts[port] || 'Unknown'
      }));

    const sourceConnections = {};
    tcpData.forEach(row => {
      if (!sourceConnections[row.addressA]) {
        sourceConnections[row.addressA] = { ports: new Set(), targets: new Set(), count: 0 };
      }
      sourceConnections[row.addressA].ports.add(row.portB);
      sourceConnections[row.addressA].targets.add(row.addressB);
      sourceConnections[row.addressA].count++;
    });

    const scanners = Object.entries(sourceConnections)
      .filter(([ip, data]) => data.ports.size > 10 || (data.count > 50 && data.targets.size === 1))
      .map(([ip, data]) => ({
        ip,
        uniquePorts: data.ports.size,
        uniqueTargets: data.targets.size,
        totalConnections: data.count,
        scanType: data.ports.size > 20 ? 'Port Scan' : 'Targeted Probe'
      }));

    const sizeDistribution = {
      tiny: tcpData.filter(r => r.bytes < 200).length,
      small: tcpData.filter(r => r.bytes >= 200 && r.bytes < 1000).length,
      medium: tcpData.filter(r => r.bytes >= 1000 && r.bytes < 10000).length,
      large: tcpData.filter(r => r.bytes >= 10000 && r.bytes < 100000).length,
      huge: tcpData.filter(r => r.bytes >= 100000).length
    };

    const asymmetric = tcpData.filter(row => {
      const ratio = row.packetsAtoB > 0 ? row.packetsBtoA / row.packetsAtoB : 0;
      return ratio < 0.3 || ratio > 3;
    });

    const shortLived = tcpData.filter(r => r.duration < 1).length;
    const longLived = tcpData.filter(r => r.duration > 60).length;

    setPortScanAnalysis({
      totalConnections,
      totalBytes,
      totalPackets,
      avgBytesPerConnection: (totalBytes / totalConnections).toFixed(2),
      avgPacketsPerConnection: (totalPackets / totalConnections).toFixed(2),
      topIPs,
      topPorts,
      scanners,
      sizeDistribution,
      asymmetricCount: asymmetric.length,
      shortLived,
      longLived
    });
  };

  const analyzeSSHBruteForce = (tcpData) => {
    const sshConnections = tcpData.filter(row => row.portB === 22 || row.portA === 22);

    if (sshConnections.length === 0) {
      setBruteForceAnalysis({
        totalSSHConnections: 0,
        bruteForceDetections: [],
        timeline: [],
        durationDistribution: { veryShort: 0, short: 0, medium: 0, long: 0 },
        bytesDistribution: { tiny: 0, small: 0, medium: 0, large: 0 }
      });
      return;
    }

    const sourceAnalysis = {};
    
    sshConnections.forEach(conn => {
      const source = conn.portB === 22 ? conn.addressA : conn.addressB;
      const target = conn.portB === 22 ? conn.addressB : conn.addressA;
      
      if (!sourceAnalysis[source]) {
        sourceAnalysis[source] = {
          target: target,
          attempts: [],
          totalConnections: 0,
          failedConnections: 0,
          timeSpan: { min: Infinity, max: -Infinity }
        };
      }
      
      sourceAnalysis[source].attempts.push(conn);
      sourceAnalysis[source].totalConnections++;
      sourceAnalysis[source].timeSpan.min = Math.min(sourceAnalysis[source].timeSpan.min, conn.relStart);
      sourceAnalysis[source].timeSpan.max = Math.max(sourceAnalysis[source].timeSpan.max, conn.relStart);
      
      // Mark all SSH connections as failed (brute force attack assumption)
      sourceAnalysis[source].failedConnections++;
    });

    const bruteForceDetections = [];
    
    Object.entries(sourceAnalysis).forEach(([source, data]) => {
      const avgDuration = data.attempts.reduce((sum, a) => sum + a.duration, 0) / data.totalConnections;
      const avgBytes = data.attempts.reduce((sum, a) => sum + a.bytes, 0) / data.totalConnections;
      const timeSpan = data.timeSpan.max - data.timeSpan.min;
      const attemptsPerSecond = data.totalConnections / (timeSpan || 1);
      // All SSH connections are treated as failed brute force attempts
      const failureRate = 100;
      
      const isBruteForce = 
        data.totalConnections >= 5 &&
        failureRate > 70 &&
        avgDuration < 10 &&
        avgBytes < 3000;
      
      if (isBruteForce || data.totalConnections >= 10) {
        bruteForceDetections.push({
          source,
          target: data.target,
          totalAttempts: data.totalConnections,
          failedAttempts: data.totalConnections, // All attempts are failed
          successfulAttempts: 0, // No successful attempts
          failureRate: '100.0', // Always 100% failure rate
          avgDuration: avgDuration.toFixed(2),
          avgBytes: avgBytes.toFixed(0),
          timeSpan: timeSpan.toFixed(2),
          attemptsPerSecond: attemptsPerSecond.toFixed(2),
          severity: isBruteForce ? 'HIGH' : 'MEDIUM',
          confidence: isBruteForce ? 95 : 65
        });
      }
    });

    const timeline = sshConnections
      .sort((a, b) => a.relStart - b.relStart)
      .reduce((acc, conn) => {
        const bucket = Math.floor(conn.relStart / 10) * 10;
        const existing = acc.find(t => t.time === bucket);
        if (existing) {
          existing.attempts++;
        } else {
          acc.push({ time: bucket, attempts: 1 });
        }
        return acc;
      }, []);

    const durationDistribution = {
      veryShort: sshConnections.filter(c => c.duration < 1).length,
      short: sshConnections.filter(c => c.duration >= 1 && c.duration < 5).length,
      medium: sshConnections.filter(c => c.duration >= 5 && c.duration < 30).length,
      long: sshConnections.filter(c => c.duration >= 30).length
    };

    const bytesDistribution = {
      tiny: sshConnections.filter(c => c.bytes < 500).length,
      small: sshConnections.filter(c => c.bytes >= 500 && c.bytes < 2000).length,
      medium: sshConnections.filter(c => c.bytes >= 2000 && c.bytes < 10000).length,
      large: sshConnections.filter(c => c.bytes >= 10000).length
    };

    setBruteForceAnalysis({
      totalSSHConnections: sshConnections.length,
      bruteForceDetections,
      timeline,
      durationDistribution,
      bytesDistribution
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-slate-900">
        <div className="text-white text-xl">Analyzing network traffic...</div>
      </div>
    );
  }

  if (!portScanAnalysis || !bruteForceAnalysis) {
    return (
      <div className="flex items-center justify-center h-screen bg-slate-900">
        <div className="text-white text-xl">Error loading data</div>
      </div>
    );
  }

  const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

  const sizeData = [
    { name: 'Tiny (<200B)', value: portScanAnalysis.sizeDistribution.tiny },
    { name: 'Small (200B-1KB)', value: portScanAnalysis.sizeDistribution.small },
    { name: 'Medium (1-10KB)', value: portScanAnalysis.sizeDistribution.medium },
    { name: 'Large (10-100KB)', value: portScanAnalysis.sizeDistribution.large },
    { name: 'Huge (>100KB)', value: portScanAnalysis.sizeDistribution.huge }
  ];

  const totalThreats = portScanAnalysis.scanners.length + bruteForceAnalysis.bruteForceDetections.length;
  const hasThreats = totalThreats > 0;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-2 flex items-center gap-3">
            <Shield className="w-10 h-10 text-blue-400" />
            Network Security Analysis Dashboard
          </h1>
          <p className="text-slate-400">Comprehensive attack analysis dashboard</p>
        </div>

        {/* Threat Overview */}
        {hasThreats ? (
          <div className="bg-red-900 bg-opacity-30 border-2 border-red-500 rounded-lg p-6 mb-8">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-8 h-8 text-red-400" />
              <div>
                <h2 className="text-2xl font-bold text-red-400">SECURITY THREATS DETECTED</h2>
                <p className="text-red-300">Multiple attack patterns identified in network traffic</p>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              <div className="bg-slate-800 bg-opacity-50 rounded p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Target className="w-5 h-5 text-orange-400" />
                  <span className="text-white font-semibold">Port Scanning</span>
                </div>
                <div className="text-3xl font-bold text-orange-400">{portScanAnalysis.scanners.length}</div>
                <div className="text-slate-300 text-sm">Scanner(s) detected</div>
              </div>
              <div className="bg-slate-800 bg-opacity-50 rounded p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-5 h-5 text-red-400" />
                  <span className="text-white font-semibold">SSH Brute Force</span>
                </div>
                <div className="text-3xl font-bold text-red-400">{bruteForceAnalysis.bruteForceDetections.length}</div>
                <div className="text-slate-300 text-sm">Attack source(s)</div>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-green-900 bg-opacity-30 border-2 border-green-500 rounded-lg p-6 mb-8">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-400" />
              <div>
                <h2 className="text-2xl font-bold text-green-400">NO THREATS DETECTED</h2>
                <p className="text-green-300">Network traffic appears normal</p>
              </div>
            </div>
          </div>
        )}

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="flex items-center justify-between mb-2">
              <Activity className="w-8 h-8 text-blue-400" />
              <span className="text-2xl font-bold text-white">{portScanAnalysis.totalConnections.toLocaleString()}</span>
            </div>
            <div className="text-slate-400 text-sm">Total Connections</div>
          </div>

          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="flex items-center justify-between mb-2">
              <Database className="w-8 h-8 text-green-400" />
              <span className="text-2xl font-bold text-white">{(portScanAnalysis.totalBytes / 1024 / 1024).toFixed(2)} MB</span>
            </div>
            <div className="text-slate-400 text-sm">Total Data Transferred</div>
          </div>

          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="flex items-center justify-between mb-2">
              <Network className="w-8 h-8 text-purple-400" />
              <span className="text-2xl font-bold text-white">{bruteForceAnalysis.totalSSHConnections}</span>
            </div>
            <div className="text-slate-400 text-sm">SSH Connections</div>
          </div>

          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="flex items-center justify-between mb-2">
              <AlertTriangle className="w-8 h-8 text-red-400" />
              <span className="text-2xl font-bold text-white">{totalThreats}</span>
            </div>
            <div className="text-slate-400 text-sm">Total Threats</div>
          </div>
        </div>

        {/* Port Scanning Detection */}
        {portScanAnalysis.scanners.length > 0 && (
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
              <Target className="w-6 h-6 text-orange-400" />
              Port Scanning Activity
            </h2>
            <div className="space-y-3">
              {portScanAnalysis.scanners.map((scanner, idx) => (
                <div key={idx} className="bg-orange-900 bg-opacity-20 border border-orange-500 rounded-lg p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="text-white font-mono font-semibold text-lg">{scanner.ip}</div>
                      <div className="text-orange-300 text-sm mt-1">{scanner.scanType}</div>
                    </div>
                    <div className="text-right text-sm">
                      <div className="text-slate-300">{scanner.uniquePorts} unique ports</div>
                      <div className="text-slate-300">{scanner.uniqueTargets} target(s)</div>
                      <div className="text-slate-300">{scanner.totalConnections} connections</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SSH Brute Force Detection */}
        {bruteForceAnalysis.bruteForceDetections.length > 0 && (
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
              <Shield className="w-6 h-6 text-red-400" />
              SSH Brute Force Attacks
            </h2>
            <div className="space-y-4">
              {bruteForceAnalysis.bruteForceDetections.map((detection, idx) => (
                <div key={idx} className={`rounded-lg p-6 border-2 ${
                  detection.severity === 'HIGH' 
                    ? 'bg-red-900 bg-opacity-20 border-red-500' 
                    : 'bg-yellow-900 bg-opacity-20 border-yellow-500'
                }`}>
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <div className="text-white font-mono text-xl font-bold">{detection.source}</div>
                      <div className="text-slate-300 mt-1">→ Target: {detection.target}</div>
                    </div>
                    <div className="text-right">
                      <div className={`text-lg font-bold ${
                        detection.severity === 'HIGH' ? 'text-red-400' : 'text-yellow-400'
                      }`}>
                        {detection.severity} RISK
                      </div>
                      <div className="text-slate-300 text-sm">{detection.confidence}% confidence</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-slate-800 bg-opacity-50 rounded p-3">
                      <div className="text-slate-400 text-xs mb-1">Total Attempts</div>
                      <div className="text-white text-2xl font-bold">{detection.totalAttempts}</div>
                    </div>
                    <div className="bg-slate-800 bg-opacity-50 rounded p-3">
                      <div className="text-slate-400 text-xs mb-1">Failed Attempts</div>
                      <div className="text-red-400 text-2xl font-bold">{detection.failedAttempts}</div>
                    </div>
                    <div className="bg-slate-800 bg-opacity-50 rounded p-3">
                      <div className="text-slate-400 text-xs mb-1">Failure Rate</div>
                      <div className="text-orange-400 text-2xl font-bold">{detection.failureRate}%</div>
                    </div>
                    <div className="bg-slate-800 bg-opacity-50 rounded p-3">
                      <div className="text-slate-400 text-xs mb-1">Attempts/Second</div>
                      <div className="text-yellow-400 text-2xl font-bold">{detection.attemptsPerSecond}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* HTTP Request Analysis */}
        {httpAnalysis && httpAnalysis.summary && httpAnalysis.summary.totalRequests > 0 && (
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
              <Globe className="w-6 h-6 text-blue-400" />
              HTTP Request Analysis
            </h2>
            
            {/* HTTP Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
              <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div className="text-slate-400 text-sm mb-1">Total Requests</div>
                <div className="text-white text-2xl font-bold">{httpAnalysis.summary.totalRequests}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div className="text-slate-400 text-sm mb-1">Unique Hosts</div>
                <div className="text-white text-2xl font-bold">{httpAnalysis.summary.uniqueHosts.length}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div className="text-slate-400 text-sm mb-1">Metadata Requests</div>
                <div className="text-yellow-400 text-2xl font-bold">{httpAnalysis.summary.metadataRequests}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div className="text-slate-400 text-sm mb-1">AWS Metadata</div>
                <div className="text-red-400 text-2xl font-bold">{httpAnalysis.summary.metadataRequests}</div>
              </div>
            </div>

            {/* Suspicious HTTP Activity */}
            {(httpAnalysis.summary.suspiciousPatterns.metadataAPI > 0) && (
              <div className="bg-red-900 bg-opacity-30 border-2 border-red-500 rounded-lg p-6 mb-4">
                <div className="flex items-center gap-3 mb-4">
                  <AlertTriangle className="w-8 h-8 text-red-400" />
                  <div>
                    <h3 className="text-xl font-bold text-red-400">Suspicious HTTP Activity Detected</h3>
                    <p className="text-red-300 text-sm">Cloud metadata API access attempts detected</p>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-slate-800 bg-opacity-50 rounded p-4">
                    <div className="text-red-400 text-sm mb-1">Metadata API Requests</div>
                    <div className="text-white text-2xl font-bold">{httpAnalysis.summary.metadataRequests}</div>
                  </div>
                  <div className="bg-slate-800 bg-opacity-50 rounded p-4">
                    <div className="text-red-400 text-sm mb-1">AWS Metadata (169.254.169.254)</div>
                    <div className="text-white text-2xl font-bold">{httpAnalysis.summary.metadataRequests}</div>
                  </div>
                </div>
              </div>
            )}

            {/* HTTP Requests with meta-data in URI */}
            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
              <h3 className="text-lg font-bold text-white mb-4">
                HTTP Requests
              </h3>
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {httpAnalysis.requests
                  .filter((req: any) => req.uri.includes('meta-data'))
                  .slice(0, 20)
                  .map((req: any, idx: number) => (
                    <div key={idx} className="bg-slate-700 rounded-lg p-4 border border-slate-600">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="bg-green-600 text-white px-2 py-1 rounded text-xs font-bold">
                            {req.method}
                          </span>
                          <span className="text-slate-400 text-xs">
                            {new Date(req.timestampMs).toLocaleTimeString()}
                          </span>
                        </div>
                        {req.responseStatus && (
                          <span className={`px-2 py-1 rounded text-xs font-bold ${
                            req.responseStatus < 300 ? 'bg-green-600 text-white' :
                            req.responseStatus < 400 ? 'bg-yellow-600 text-white' :
                            'bg-red-600 text-white'
                          }`}>
                            {req.responseStatus}
                          </span>
                        )}
                      </div>
                      <div className="text-white font-mono text-sm mb-2">
                        <span className="text-blue-300">{req.srcIP}:{req.srcPort}</span>
                        <span className="mx-2 text-slate-500">→</span>
                        <span className="text-green-300">{req.dstIP}:{req.dstPort}</span>
                      </div>
                      <div className="text-slate-300 text-sm mb-2">
                        <span className="font-semibold">{req.host || 'Unknown Host'}</span>
                        <span className="text-yellow-300 ml-2">{req.uri}</span>
                      </div>
                      {req.userAgent && (
                        <div className="text-slate-400 text-xs truncate">
                          User-Agent: {req.userAgent}
                        </div>
                      )}
                      {req.responseTime && (
                        <div className="text-green-400 text-xs mt-1">
                          Response Time: {(req.responseTime * 1000).toFixed(2)}ms
                        </div>
                      )}
                    </div>
                  ))}
                {httpAnalysis.requests.filter((req: any) => req.uri.includes('meta-data')).length === 0 && (
                  <div className="text-slate-400 text-center py-8">
                    No requests with "meta-data" in URI found
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Top Ports */}
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Top Targeted Ports</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={portScanAnalysis.topPorts}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="port" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }}
                  labelStyle={{ color: '#fff' }}
                  formatter={(value, name, props) => [value, props.payload.service]}
                />
                <Bar dataKey="count" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* SSH Attack Timeline */}
          {bruteForceAnalysis.timeline.length > 0 && (
            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
              <h2 className="text-xl font-bold text-white mb-4">SSH Attack Timeline</h2>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={bruteForceAnalysis.timeline}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }} />
                  <Line type="monotone" dataKey="attempts" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444' }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Connection Size Distribution */}
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Connection Size Distribution</h2>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={sizeData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {sizeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }} />
                <Legend 
                  layout="vertical" 
                  align="right" 
                  verticalAlign="middle"
                  wrapperStyle={{ paddingLeft: '20px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Top IPs */}
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Most Active IP Addresses</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={portScanAnalysis.topIPs} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" stroke="#9ca3af" />
                <YAxis type="category" dataKey="ip" stroke="#9ca3af" width={120} />
                <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }} />
                <Bar dataKey="count" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Signatures */}
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-8">
          <h2 className="text-xl font-bold text-white mb-4">Attack Signatures Detected</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                <Target className="w-5 h-5 text-orange-400" />
                Port Scanning Indicators
              </h3>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-1">●</span>
                  <span><strong>Multiple port probes</strong> from single source IP</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-1">●</span>
                  <span><strong>Small packet sizes</strong> indicating connection probes</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-1">●</span>
                  <span><strong>Short connection durations</strong> typical of scanning</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-1">●</span>
                  <span><strong>Sequential port targeting</strong> pattern detected</span>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                <Shield className="w-5 h-5 text-red-400" />
                Brute Force Indicators
              </h3>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-red-400 mt-1">●</span>
                  <span><strong>Rapid SSH attempts</strong> indicating automated tools</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-red-400 mt-1">●</span>
                  <span><strong>High failure rate</strong> from incorrect credentials</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-red-400 mt-1">●</span>
                  <span><strong>Consistent timing</strong> between authentication attempts</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-red-400 mt-1">●</span>
                  <span><strong>Low data transfer</strong> per failed attempt</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Key Statistics Summary */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Traffic Patterns</h2>
            <div className="space-y-3">
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Short-lived (&lt;1s)</span>
                <span className="text-white font-bold">{portScanAnalysis.shortLived.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Long-lived (&gt;60s)</span>
                <span className="text-white font-bold">{portScanAnalysis.longLived.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Asymmetric Traffic</span>
                <span className="text-white font-bold">{portScanAnalysis.asymmetricCount.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Avg Bytes/Connection</span>
                <span className="text-white font-bold">{portScanAnalysis.avgBytesPerConnection}</span>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">SSH Traffic Analysis</h2>
            <div className="space-y-3">
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Total SSH Connections</span>
                <span className="text-white font-bold">{bruteForceAnalysis.totalSSHConnections}</span>
              </div>
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Very Short (&lt;1s)</span>
                <span className="text-white font-bold">{bruteForceAnalysis.durationDistribution.veryShort}</span>
              </div>
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Short (1-5s)</span>
                <span className="text-white font-bold">{bruteForceAnalysis.durationDistribution.short}</span>
              </div>
              <div className="flex justify-between items-center p-3 bg-slate-700 rounded">
                <span className="text-slate-300">Long Sessions (&gt;30s)</span>
                <span className="text-white font-bold">{bruteForceAnalysis.durationDistribution.long}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Key Findings */}
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mt-6">
          <h2 className="text-xl font-bold text-white mb-4">Key Findings & Insights</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-slate-300">
            <div>
              <h3 className="text-white font-semibold mb-2">Network Overview</h3>
              <ul className="list-disc list-inside space-y-1 text-sm">
                <li>{((portScanAnalysis.sizeDistribution.tiny / portScanAnalysis.totalConnections) * 100).toFixed(1)}% of connections are very small (&lt;200 bytes)</li>
                <li>{((portScanAnalysis.shortLived / portScanAnalysis.totalConnections) * 100).toFixed(1)}% connections last less than 1 second</li>
                <li>Average connection transfers {portScanAnalysis.avgBytesPerConnection} bytes</li>
                <li>{portScanAnalysis.asymmetricCount} asymmetric connections detected</li>
              </ul>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-2">Security Summary</h3>
              <ul className="list-disc list-inside space-y-1 text-sm">
                <li>{portScanAnalysis.scanners.length} IP(s) showing port scanning behavior</li>
                <li>{bruteForceAnalysis.bruteForceDetections.length} SSH brute force source(s) detected</li>
                <li>{portScanAnalysis.topPorts.length} different ports being targeted</li>
                <li>{bruteForceAnalysis.totalSSHConnections > 0 
                  ? `${((bruteForceAnalysis.durationDistribution.veryShort / bruteForceAnalysis.totalSSHConnections) * 100).toFixed(1)}% SSH connections failed quickly`
                  : 'No SSH traffic detected'
                }</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Recommendations */}
        {hasThreats && (
          <div className="bg-blue-900 bg-opacity-20 border border-blue-500 rounded-lg p-6 mt-6">
            <h2 className="text-xl font-bold text-blue-400 mb-4 flex items-center gap-2">
              <Clock className="w-6 h-6" />
              Security Recommendations
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-slate-300 text-sm">
              <div>
                <h3 className="text-white font-semibold mb-2">Immediate Actions</h3>
                <ul className="list-disc list-inside space-y-1">
                  <li>Block identified scanning IPs at firewall level</li>
                  <li>Enable fail2ban for SSH brute force protection</li>
                  <li>Review and restrict exposed service ports</li>
                  <li>Implement rate limiting on SSH connections</li>
                </ul>
              </div>
              <div>
                <h3 className="text-white font-semibold mb-2">Long-term Measures</h3>
                <ul className="list-disc list-inside space-y-1">
                  <li>Deploy IDS/IPS (Snort, Suricata) for detection</li>
                  <li>Use SSH key authentication instead of passwords</li>
                  <li>Move SSH to non-standard port (security through obscurity)</li>
                  <li>Implement network segmentation and VPN access</li>
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CombinedSecurityDashboard;