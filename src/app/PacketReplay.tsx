'use client';

import React, { useState, useEffect, useRef } from 'react';
import { Play, Pause, SkipForward, SkipBack, AlertCircle, CheckCircle, Info, Zap, Network, Database, Code, Filter, Search, Download } from 'lucide-react';

interface PacketData {
  id: number;
  timestamp: number;
  timestampMs: string;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  length: number;
  info: string;
  payload: string;
  headers: any;
  tcpFlags?: string[];
  httpMethod?: string;
  httpPath?: string;
  httpStatus?: number;
  httpHeaders?: Record<string, string>;
}

interface PacketSummary {
  totalPackets: number;
  protocols: string[];
  uniqueIPs: string[];
  httpRequests: number;
  httpResponses: number;
}

const PacketReplay = () => {
  const [packets, setPackets] = useState<PacketData[]>([]);
  const [summary, setSummary] = useState<PacketSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPacketIndex, setCurrentPacketIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [selectedPacket, setSelectedPacket] = useState<PacketData | null>(null);
  const [filterProtocol, setFilterProtocol] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showPayload, setShowPayload] = useState(true);
  
  const animationRef = useRef<number | null>(null);
  const lastUpdateRef = useRef<number>(0);

  useEffect(() => {
    loadPackets();                                                                                                                                                                                                                                                                                                                  
  }, []);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           

  useEffect(() => {
    if (isPlaying && currentPacketIndex < packets.length - 1) {
      const animate = (timestamp: number) => {                                                                                                                                                                    
        if (timestamp - lastUpdateRef.current > (1000 / playbackSpeed)) {
          setCurrentPacketIndex(prev => {
            if (prev >= packets.length - 1) {
              setIsPlaying(false);
              return prev;
            }
            return prev + 1;
          });
          lastUpdateRef.current = timestamp;
        }
        animationRef.current = requestAnimationFrame(animate);
      };
      animationRef.current = requestAnimationFrame(animate);
    } else if (!isPlaying && animationRef.current) {
      cancelAnimationFrame(animationRef.current);
    }

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [isPlaying, playbackSpeed, packets.length, currentPacketIndex]);

  const loadPackets = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/parse-pcap');
      if (!response.ok) {
        throw new Error('Failed to load packet data');
      }
      const data = await response.json();
      setPackets(data.packets || []);
      setSummary(data.summary);
      if (data.packets && data.packets.length > 0) {
        setSelectedPacket(data.packets[0]);
      }
      setLoading(false);
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  };

  const togglePlayback = () => {
    if (currentPacketIndex >= packets.length - 1) {
      setCurrentPacketIndex(0);
    }
    setIsPlaying(!isPlaying);
  };

  const stepForward = () => {
    if (currentPacketIndex < packets.length - 1) {
      setCurrentPacketIndex(currentPacketIndex + 1);
      setSelectedPacket(packets[currentPacketIndex + 1]);
    }
  };

  const stepBackward = () => {
    if (currentPacketIndex > 0) {
      setCurrentPacketIndex(currentPacketIndex - 1);
      setSelectedPacket(packets[currentPacketIndex - 1]);
    }
  };

  const getFilteredPackets = () => {
    let filtered = packets;
    
    if (filterProtocol !== 'all') {
      filtered = filtered.filter(p => p.protocol === filterProtocol);
    }
    
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(p => 
        p.srcIP.includes(term) ||
        p.dstIP.includes(term) ||
        p.protocol.toLowerCase().includes(term) ||
        p.info.toLowerCase().includes(term) ||
        (p.httpPath && p.httpPath.toLowerCase().includes(term))
      );
    }
    
    return filtered;
  };

  const getProtocolColor = (protocol: string) => {
    const colors: Record<string, string> = {
      'HTTP': 'bg-green-500',
      'TCP': 'bg-blue-500',
      'UDP': 'bg-purple-500',
      'ICMP': 'bg-yellow-500',
      'DNS': 'bg-pink-500',
      'SSH': 'bg-red-500'
    };
    return colors[protocol] || 'bg-gray-500';
  };

  const getProtocolIcon = (protocol: string) => {
    switch (protocol) {
      case 'HTTP': return <Network className="w-4 h-4" />;
      case 'TCP': return <Zap className="w-4 h-4" />;
      case 'UDP': return <Database className="w-4 h-4" />;
      default: return <Code className="w-4 h-4" />;
    }
  };

  const formatTimestamp = (timestamp: number) => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString() + '.' + (timestamp % 1).toFixed(6).substring(2);
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-blue-500 mb-4"></div>
          <div className="text-white text-xl">Parsing PCAP file...</div>
          <div className="text-slate-400 text-sm mt-2">Extracting packet data and analyzing traffic</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="bg-red-900 bg-opacity-30 border-2 border-red-500 rounded-lg p-8 max-w-md">
          <AlertCircle className="w-12 h-12 text-red-400 mb-4" />
          <h2 className="text-2xl font-bold text-red-400 mb-2">Error Loading Packets</h2>
          <p className="text-red-300">{error}</p>
        </div>
      </div>
    );
  }

  const filteredPackets = getFilteredPackets();
  const currentPacket = packets[currentPacketIndex];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-2 flex items-center gap-3">
            <Network className="w-10 h-10 text-blue-400" />
            Packet Replay & Analysis
          </h1>
          <p className="text-slate-400">Real-time packet visualization and deep inspection</p>
        </div>

        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 transform transition-all hover:scale-105">
              <div className="flex items-center justify-between mb-2">
                <Database className="w-8 h-8 text-blue-400" />
                <span className="text-2xl font-bold text-white">{summary.totalPackets}</span>
              </div>
              <div className="text-slate-400 text-sm">Total Packets</div>
            </div>

            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 transform transition-all hover:scale-105">
              <div className="flex items-center justify-between mb-2">
                <Code className="w-8 h-8 text-green-400" />
                <span className="text-2xl font-bold text-white">{summary.protocols.length}</span>
              </div>
              <div className="text-slate-400 text-sm">Protocols</div>
            </div>

            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 transform transition-all hover:scale-105">
              <div className="flex items-center justify-between mb-2">
                <Network className="w-8 h-8 text-purple-400" />
                <span className="text-2xl font-bold text-white">{summary.uniqueIPs.length}</span>
              </div>
              <div className="text-slate-400 text-sm">Unique IPs</div>
            </div>

            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 transform transition-all hover:scale-105">
              <div className="flex items-center justify-between mb-2">
                <Zap className="w-8 h-8 text-yellow-400" />
                <span className="text-2xl font-bold text-white">{summary.httpRequests}</span>
              </div>
              <div className="text-slate-400 text-sm">HTTP Requests</div>
            </div>

            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 transform transition-all hover:scale-105">
              <div className="flex items-center justify-between mb-2">
                <CheckCircle className="w-8 h-8 text-green-400" />
                <span className="text-2xl font-bold text-white">{summary.httpResponses}</span>
              </div>
              <div className="text-slate-400 text-sm">HTTP Responses</div>
            </div>
          </div>
        )}

        {/* Playback Controls */}
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-8">
          <div className="flex items-center gap-4 mb-4">
            <button
              onClick={stepBackward}
              disabled={currentPacketIndex === 0}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white p-3 rounded-lg transition-all transform hover:scale-110"
            >
              <SkipBack className="w-5 h-5" />
            </button>

            <button
              onClick={togglePlayback}
              className="bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-lg transition-all transform hover:scale-110 flex items-center gap-2"
            >
              {isPlaying ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
              {isPlaying ? 'Pause' : 'Play'}
            </button>

            <button
              onClick={stepForward}
              disabled={currentPacketIndex >= packets.length - 1}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white p-3 rounded-lg transition-all transform hover:scale-110"
            >
              <SkipForward className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 ml-4">
              <span className="text-slate-400 text-sm">Speed:</span>
              {[0.5, 1, 2, 5, 10].map(speed => (
                <button
                  key={speed}
                  onClick={() => setPlaybackSpeed(speed)}
                  className={`px-3 py-1 rounded ${
                    playbackSpeed === speed
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  } transition-all`}
                >
                  {speed}x
                </button>
              ))}
            </div>

            <div className="flex-1 ml-4">
              <div className="relative">
                <input
                  type="range"
                  min="0"
                  max={packets.length - 1}
                  value={currentPacketIndex}
                  onChange={(e) => {
                    setCurrentPacketIndex(parseInt(e.target.value));
                    setSelectedPacket(packets[parseInt(e.target.value)]);
                  }}
                  className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
                />
                <div className="flex justify-between text-slate-400 text-xs mt-1">
                  <span>Packet {currentPacketIndex + 1}</span>
                  <span>{packets.length} total</span>
                </div>
              </div>
            </div>
          </div>

          {/* Current Packet Visualization */}
          {currentPacket && (
            <div className="bg-gradient-to-r from-blue-900 to-purple-900 bg-opacity-30 rounded-lg p-4 border border-blue-500 animate-pulse">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`${getProtocolColor(currentPacket.protocol)} text-white px-4 py-2 rounded-lg font-bold flex items-center gap-2`}>
                    {getProtocolIcon(currentPacket.protocol)}
                    {currentPacket.protocol}
                  </div>
                  <div className="text-white font-mono">
                    <span className="text-blue-300">{currentPacket.srcIP}:{currentPacket.srcPort}</span>
                    <span className="mx-2 text-slate-400">→</span>
                    <span className="text-green-300">{currentPacket.dstIP}:{currentPacket.dstPort}</span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-slate-300 text-sm">{formatTimestamp(currentPacket.timestamp)}</div>
                  <div className="text-slate-400 text-xs">{formatBytes(currentPacket.length)}</div>
                </div>
              </div>
              {currentPacket.info && (
                <div className="mt-2 text-slate-300 text-sm">{currentPacket.info}</div>
              )}
            </div>
          )}
        </div>

        {/* Filters and Search */}
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-8">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Filter className="w-5 h-5 text-slate-400" />
              <select
                value={filterProtocol}
                onChange={(e) => setFilterProtocol(e.target.value)}
                className="bg-slate-700 text-white px-4 py-2 rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
              >
                <option value="all">All Protocols</option>
                {summary?.protocols.map(protocol => (
                  <option key={protocol} value={protocol}>{protocol}</option>
                ))}
              </select>
            </div>

            <div className="flex-1 relative">
              <Search className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by IP, protocol, or info..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-700 text-white pl-10 pr-4 py-2 rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
              />
            </div>

            <button
              onClick={() => setShowPayload(!showPayload)}
              className={`px-4 py-2 rounded-lg transition-all ${
                showPayload
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              {showPayload ? 'Hide' : 'Show'} Payload
            </button>
          </div>
        </div>

        {/* Main Content: Packet List and Details */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Packet List */}
          <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
            <div className="bg-slate-700 p-4 border-b border-slate-600">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Database className="w-6 h-6 text-blue-400" />
                Packet List ({filteredPackets.length})
              </h2>
            </div>
            <div className="overflow-y-auto" style={{ maxHeight: '600px' }}>
              {filteredPackets.map((packet, index) => (
                <div
                  key={packet.id}
                  onClick={() => setSelectedPacket(packet)}
                  className={`p-4 border-b border-slate-700 cursor-pointer transition-all transform hover:scale-[1.02] ${
                    selectedPacket?.id === packet.id
                      ? 'bg-blue-900 bg-opacity-50 border-l-4 border-blue-500'
                      : 'hover:bg-slate-700'
                  } ${
                    packet.id === currentPacket?.id
                      ? 'border-r-4 border-green-500'
                      : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 text-sm">#{packet.id}</span>
                      <div className={`${getProtocolColor(packet.protocol)} text-white px-2 py-1 rounded text-xs font-bold flex items-center gap-1`}>
                        {getProtocolIcon(packet.protocol)}
                        {packet.protocol}
                      </div>
                    </div>
                    <span className="text-slate-400 text-xs">{formatBytes(packet.length)}</span>
                  </div>
                  <div className="text-white font-mono text-sm mb-1">
                    <span className="text-blue-300">{packet.srcIP}:{packet.srcPort}</span>
                    <span className="mx-2 text-slate-500">→</span>
                    <span className="text-green-300">{packet.dstIP}:{packet.dstPort}</span>
                  </div>
                  {packet.info && (
                    <div className="text-slate-400 text-xs truncate">{packet.info}</div>
                  )}
                  {packet.tcpFlags && packet.tcpFlags.length > 0 && (
                    <div className="mt-1 flex gap-1">
                      {packet.tcpFlags.map(flag => (
                        <span key={flag} className="bg-slate-700 text-blue-300 px-2 py-0.5 rounded text-xs">
                          {flag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Packet Details */}
          <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
            <div className="bg-slate-700 p-4 border-b border-slate-600">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Info className="w-6 h-6 text-green-400" />
                Packet Details
              </h2>
            </div>
            <div className="overflow-y-auto p-4" style={{ maxHeight: '600px' }}>
              {selectedPacket ? (
                <div className="space-y-4">
                  {/* Basic Info */}
                  <div className="bg-slate-700 rounded-lg p-4">
                    <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                      <Network className="w-5 h-5 text-blue-400" />
                      Basic Information
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Packet #:</span>
                        <span className="text-white font-mono">{selectedPacket.id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Timestamp:</span>
                        <span className="text-white font-mono">{formatTimestamp(selectedPacket.timestamp)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Protocol:</span>
                        <span className={`${getProtocolColor(selectedPacket.protocol)} text-white px-2 py-1 rounded font-bold`}>
                          {selectedPacket.protocol}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Length:</span>
                        <span className="text-white">{formatBytes(selectedPacket.length)}</span>
                      </div>
                    </div>
                  </div>

                  {/* Network Layer */}
                  <div className="bg-slate-700 rounded-lg p-4">
                    <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                      <Zap className="w-5 h-5 text-yellow-400" />
                      Network Layer
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Source IP:</span>
                        <span className="text-blue-300 font-mono">{selectedPacket.srcIP}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Source Port:</span>
                        <span className="text-blue-300 font-mono">{selectedPacket.srcPort}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Destination IP:</span>
                        <span className="text-green-300 font-mono">{selectedPacket.dstIP}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Destination Port:</span>
                        <span className="text-green-300 font-mono">{selectedPacket.dstPort}</span>
                      </div>
                    </div>
                  </div>

                  {/* TCP Flags */}
                  {selectedPacket.tcpFlags && selectedPacket.tcpFlags.length > 0 && (
                    <div className="bg-slate-700 rounded-lg p-4">
                      <h3 className="text-white font-semibold mb-3">TCP Flags</h3>
                      <div className="flex flex-wrap gap-2">
                        {selectedPacket.tcpFlags.map(flag => (
                          <span key={flag} className="bg-blue-600 text-white px-3 py-1 rounded-full text-sm font-bold">
                            {flag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* HTTP Details */}
                  {(selectedPacket.httpMethod || selectedPacket.httpStatus) && (
                    <div className="bg-gradient-to-r from-green-900 to-blue-900 bg-opacity-30 rounded-lg p-4 border border-green-500">
                      <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                        <Network className="w-5 h-5 text-green-400" />
                        HTTP Details
                      </h3>
                      <div className="space-y-2 text-sm">
                        {selectedPacket.httpMethod && (
                          <>
                            <div className="flex justify-between">
                              <span className="text-slate-400">Method:</span>
                              <span className="text-green-300 font-bold">{selectedPacket.httpMethod}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-400">Path:</span>
                              <span className="text-green-300 font-mono text-xs break-all">{selectedPacket.httpPath}</span>
                            </div>
                          </>
                        )}
                        {selectedPacket.httpStatus && (
                          <div className="flex justify-between">
                            <span className="text-slate-400">Status:</span>
                            <span className={`font-bold ${
                              selectedPacket.httpStatus < 300 ? 'text-green-400' :
                              selectedPacket.httpStatus < 400 ? 'text-yellow-400' :
                              'text-red-400'
                            }`}>{selectedPacket.httpStatus}</span>
                          </div>
                        )}
                      </div>
                      
                      {selectedPacket.httpHeaders && Object.keys(selectedPacket.httpHeaders).length > 0 && (
                        <div className="mt-3">
                          <h4 className="text-white font-semibold mb-2 text-sm">Headers:</h4>
                          <div className="bg-slate-800 bg-opacity-50 rounded p-3 space-y-1 max-h-40 overflow-y-auto">
                            {Object.entries(selectedPacket.httpHeaders).map(([key, value]) => (
                              <div key={key} className="text-xs">
                                <span className="text-blue-300">{key}:</span>{' '}
                                <span className="text-slate-300">{value}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Payload */}
                  {showPayload && selectedPacket.payload && (
                    <div className="bg-slate-700 rounded-lg p-4">
                      <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                        <Code className="w-5 h-5 text-purple-400" />
                        Payload
                      </h3>
                      <div className="bg-black bg-opacity-50 rounded p-3 overflow-x-auto">
                        <pre className="text-green-400 text-xs font-mono whitespace-pre-wrap break-all">
                          {selectedPacket.payload}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* Ethernet Headers */}
                  {selectedPacket.headers && (
                    <div className="bg-slate-700 rounded-lg p-4">
                      <h3 className="text-white font-semibold mb-3">Ethernet Headers</h3>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-slate-400">Source MAC:</span>
                          <span className="text-white font-mono text-xs">{selectedPacket.headers.srcMac}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Dest MAC:</span>
                          <span className="text-white font-mono text-xs">{selectedPacket.headers.dstMac}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">EtherType:</span>
                          <span className="text-white font-mono">{selectedPacket.headers.etherType}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-12">
                  <Info className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                  <p className="text-slate-400">Select a packet to view details</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PacketReplay;
