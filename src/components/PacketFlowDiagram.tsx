'use client';

import React, { useEffect, useState } from 'react';
import { ArrowRight, Server, Laptop } from 'lucide-react';

interface PacketData {
  id: number;
  timestamp: number;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  tcpFlags?: string[];
  httpMethod?: string;
  httpPath?: string;
  httpStatus?: number;
  info: string;
}

interface PacketFlowDiagramProps {
  currentPacket: PacketData | null;
  packets: PacketData[];
  currentIndex: number;
}

interface FlowLine {
  id: number;
  direction: 'left-to-right' | 'right-to-left';
  label: string;
  flags: string[];
  animate: boolean;
}

const PacketFlowDiagram: React.FC<PacketFlowDiagramProps> = ({ currentPacket, packets, currentIndex }) => {
  const [flowLines, setFlowLines] = useState<FlowLine[]>([]);
  const [leftDevice, setLeftDevice] = useState<{ ip: string; label: string }>({ ip: '', label: 'Device A' });
  const [rightDevice, setRightDevice] = useState<{ ip: string; label: string }>({ ip: '', label: 'Device B' });

  useEffect(() => {
    if (!currentPacket) return;

    // Determine devices based on the first packet or maintain consistency
    if (!leftDevice.ip && !rightDevice.ip && packets.length > 0) {
      const firstPacket = packets[0];
      setLeftDevice({ ip: firstPacket.srcIP, label: 'Client' });
      setRightDevice({ ip: firstPacket.dstIP, label: 'Server' });
    }

    // Determine direction
    const isLeftToRight = currentPacket.srcIP === leftDevice.ip;
    
    // Create label
    let label = '';
    if (currentPacket.httpMethod) {
      label = `${currentPacket.httpMethod} ${currentPacket.httpPath || ''}`;
    } else if (currentPacket.httpStatus) {
      label = `HTTP ${currentPacket.httpStatus}`;
    } else {
      label = `${currentPacket.protocol}`;
    }

    const portInfo = `(${currentPacket.srcPort} → ${currentPacket.dstPort})`;
    const flags = currentPacket.tcpFlags || [];

    // Add new flow line with animation
    const newLine: FlowLine = {
      id: currentPacket.id,
      direction: isLeftToRight ? 'left-to-right' : 'right-to-left',
      label: `${label} ${portInfo}`,
      flags,
      animate: true,
    };

    setFlowLines(prev => {
      const updated = [...prev, newLine];
      // Keep only last 10 lines for performance
      return updated.slice(-10);
    });

    // Remove animation after delay
    const timer = setTimeout(() => {
      setFlowLines(prev =>
        prev.map(line =>
          line.id === currentPacket.id ? { ...line, animate: false } : line
        )
      );
    }, 1000);

    return () => clearTimeout(timer);
  }, [currentPacket, leftDevice.ip, rightDevice.ip, packets]);

  if (!currentPacket) {
    return (
      <div className="bg-slate-800 rounded-lg border border-slate-700 p-8 flex items-center justify-center">
        <p className="text-slate-400">No packet selected</p>
      </div>
    );
  }

  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg border border-slate-700 p-8 overflow-hidden">
      <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
        <ArrowRight className="w-6 h-6 text-blue-400" />
        Packet Flow Visualization
      </h2>

      <div className="relative flex gap-8">
        {/* Left Device */}
        <div className="flex flex-col items-center space-y-2 w-1/4">
          <div className="bg-blue-600 p-4 rounded-lg shadow-lg transform hover:scale-105 transition-all">
            <Laptop className="w-12 h-12 text-white" />
          </div>
          <div className="text-center">
            <div className="text-white font-bold text-lg">{leftDevice.label}</div>
            <div className="text-blue-300 font-mono text-sm bg-slate-700 px-3 py-1 rounded mt-1">
              {leftDevice.ip}
            </div>
          </div>
        </div>

        {/* Flow Lines - Center */}
        <div className="flex-1 flex flex-col justify-start">
          {/* Connection Line at top */}
          <div className="w-full h-1 bg-gradient-to-r from-blue-500 via-purple-500 to-green-500 rounded-full shadow-lg mb-8"></div>
          
          {/* Packet flow area */}
          <div className="space-y-4 min-h-[400px] max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
          {flowLines.map((line, index) => (
            <div
              key={line.id}
              className={`relative transition-all duration-500 ${
                line.animate ? 'opacity-100 translate-y-0' : 'opacity-70'
              }`}
              style={{
                animation: line.animate ? 'slideIn 0.5s ease-out' : 'none',
              }}
            >
              {line.direction === 'left-to-right' ? (
                // Left to Right Arrow
                <div className="flex items-center gap-2">
                  <div className="w-1/3"></div>
                  <div className="flex-1 relative">
                    <div className={`relative ${line.animate ? 'animate-pulse' : ''}`}>
                      {/* Arrow Line */}
                      <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-400 to-green-400"></div>
                      {/* Arrow Head */}
                      <div className="absolute top-1/2 right-0 transform -translate-y-1/2">
                        <div className="w-0 h-0 border-t-8 border-t-transparent border-b-8 border-b-transparent border-l-8 border-l-green-400"></div>
                      </div>
                      {/* Animated Dot */}
                      {line.animate && (
                        <div
                          className="absolute top-1/2 transform -translate-y-1/2 w-3 h-3 bg-blue-400 rounded-full shadow-lg"
                          style={{
                            animation: 'moveDotRight 1s ease-in-out',
                          }}
                        ></div>
                      )}
                    </div>
                    {/* Label */}
                    <div className="mt-4 text-center">
                      <div className="text-blue-300 text-sm font-mono bg-slate-700 bg-opacity-50 px-4 py-2 rounded inline-block min-w-[300px] whitespace-nowrap">
                        {line.label}
                      </div>
                      {line.flags.length > 0 && (
                        <div className="mt-1 flex justify-center gap-1 flex-wrap">
                          {line.flags.map((flag, idx) => (
                            <span
                              key={idx}
                              className="bg-blue-600 text-white px-2 py-0.5 rounded text-xs font-bold"
                            >
                              {flag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="w-1/3"></div>
                </div>
              ) : (
                // Right to Left Arrow
                <div className="flex items-center gap-2">
                  <div className="w-1/3"></div>
                  <div className="flex-1 relative">
                    <div className={`relative ${line.animate ? 'animate-pulse' : ''}`}>
                      {/* Arrow Line */}
                      <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-green-400 to-blue-400"></div>
                      {/* Arrow Head */}
                      <div className="absolute top-1/2 left-0 transform -translate-y-1/2">
                        <div className="w-0 h-0 border-t-8 border-t-transparent border-b-8 border-b-transparent border-r-8 border-r-blue-400"></div>
                      </div>
                      {/* Animated Dot */}
                      {line.animate && (
                        <div
                          className="absolute top-1/2 right-0 transform -translate-y-1/2 w-3 h-3 bg-green-400 rounded-full shadow-lg"
                          style={{
                            animation: 'moveDotLeft 1s ease-in-out',
                          }}
                        ></div>
                      )}
                    </div>
                    {/* Label */}
                    <div className="mt-4 text-center">
                      <div className="text-green-300 text-sm font-mono bg-slate-700 bg-opacity-50 px-4 py-2 rounded inline-block min-w-[300px] whitespace-nowrap">
                        {line.label}
                      </div>
                      {line.flags.length > 0 && (
                        <div className="mt-1 flex justify-center gap-1 flex-wrap">
                          {line.flags.map((flag, idx) => (
                            <span
                              key={idx}
                              className="bg-green-600 text-white px-2 py-0.5 rounded text-xs font-bold"
                            >
                              {flag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="w-1/3"></div>
                </div>
              )}
            </div>
          ))}
          </div>
        </div>

        {/* Right Device */}
        <div className="flex flex-col items-center space-y-2 w-1/4">
          <div className="bg-green-600 p-4 rounded-lg shadow-lg transform hover:scale-105 transition-all">
            <Server className="w-12 h-12 text-white" />
          </div>
          <div className="text-center">
            <div className="text-white font-bold text-lg">{rightDevice.label}</div>
            <div className="text-green-300 font-mono text-sm bg-slate-700 px-3 py-1 rounded mt-1">
              {rightDevice.ip}
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes slideIn {
          from {
            opacity: 0;
            transform: translateY(-20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes moveDotRight {
          from {
            left: 0%;
          }
          to {
            left: 100%;
          }
        }

        @keyframes moveDotLeft {
          from {
            right: 0%;
          }
          to {
            right: 100%;
          }
        }

        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }

        .custom-scrollbar::-webkit-scrollbar-track {
          background: #1e293b;
          border-radius: 4px;
        }

        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #475569;
          border-radius: 4px;
        }

        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #64748b;
        }
      `}</style>
    </div>
  );
};

export default PacketFlowDiagram;
