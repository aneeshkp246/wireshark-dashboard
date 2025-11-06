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
  // Default to the requested IPs and friendly labels
  const [leftDevice, setLeftDevice] = useState<{ ip: string; label: string }>({ ip: '192.168.56.1', label: 'Client' });
  const [rightDevice, setRightDevice] = useState<{ ip: string; label: string }>({ ip: '192.168.56.101', label: 'Server' });

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

    // Replace with new single flow line
    const newLine: FlowLine = {
      id: currentPacket.id,
      direction: isLeftToRight ? 'left-to-right' : 'right-to-left',
      label: `${label} ${portInfo}`,
      flags,
      animate: true,
    };

    setFlowLines([newLine]);
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
          <div className="flex items-center justify-center min-h-[400px]">
          {flowLines.map((line, index) => (
            <div
              key={line.id}
              className="w-full"
            >
              {line.direction === 'left-to-right' ? (
                // Left to Right Arrow
                <div className="flex items-center gap-2">
                  <div className="flex-1 relative">
                    <div className="relative">
                      {/* Arrow Line */}
                      <div className="absolute top-1/2 left-0 right-0 h-1 bg-gradient-to-r from-blue-500/30 to-green-500/30 rounded-full"></div>
                      
                      {/* Animated Packet */}
                      <div
                        className="absolute top-1/2 transform -translate-y-1/2 -translate-x-1/2"
                        style={{
                          animation: 'moveDotRight 1.8s ease-in-out',
                        }}
                      >
                        <div className="relative">
                          {/* Packet glow effect */}
                          <div className="absolute inset-0 bg-blue-400 rounded-lg blur-xl opacity-60 animate-pulse"></div>
                          {/* Packet body */}
                          <div className="relative bg-gradient-to-r from-blue-500 to-blue-600 px-6 py-3 rounded-lg shadow-2xl border-2 border-blue-300">
                            <div className="text-white font-bold text-sm whitespace-nowrap">
                              {line.label}
                            </div>
                            {line.flags.length > 0 && (
                              <div className="mt-1 flex gap-1">
                                {line.flags.map((flag, idx) => (
                                  <span
                                    key={idx}
                                    className="bg-blue-700 text-white px-2 py-0.5 rounded text-xs font-bold"
                                  >
                                    {flag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          {/* Arrow head on packet */}
                          <div className="absolute top-1/2 -right-3 transform -translate-y-1/2">
                            <div className="w-0 h-0 border-t-[12px] border-t-transparent border-b-[12px] border-b-transparent border-l-[12px] border-l-blue-600"></div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                // Right to Left Arrow
                <div className="flex items-center gap-2">
                  <div className="flex-1 relative">
                    <div className="relative">
                      {/* Arrow Line */}
                      <div className="absolute top-1/2 left-0 right-0 h-1 bg-gradient-to-r from-green-500/30 to-blue-500/30 rounded-full"></div>
                      
                      {/* Animated Packet */}
                      <div
                        className="absolute top-1/2 transform -translate-y-1/2 translate-x-1/2"
                        style={{
                          animation: 'moveDotLeft 1.8s ease-in-out',
                        }}
                      >
                        <div className="relative">
                          {/* Packet glow effect */}
                          <div className="absolute inset-0 bg-green-400 rounded-lg blur-xl opacity-60 animate-pulse"></div>
                          {/* Packet body */}
                          <div className="relative bg-gradient-to-r from-green-600 to-green-500 px-6 py-3 rounded-lg shadow-2xl border-2 border-green-300">
                            <div className="text-white font-bold text-sm whitespace-nowrap">
                              {line.label}
                            </div>
                            {line.flags.length > 0 && (
                              <div className="mt-1 flex gap-1">
                                {line.flags.map((flag, idx) => (
                                  <span
                                    key={idx}
                                    className="bg-green-700 text-white px-2 py-0.5 rounded text-xs font-bold"
                                  >
                                    {flag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          {/* Arrow head on packet */}
                          <div className="absolute top-1/2 -left-3 transform -translate-y-1/2">
                            <div className="w-0 h-0 border-t-[12px] border-t-transparent border-b-[12px] border-b-transparent border-r-[12px] border-r-green-500"></div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
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
        @keyframes moveDotRight {
          0% {
            left: 0%;
            opacity: 0;
            transform: translateY(-50%) translateX(-50%) scale(0.8);
          }
          10% {
            opacity: 1;
            transform: translateY(-50%) translateX(-50%) scale(1);
          }
          90% {
            opacity: 1;
            transform: translateY(-50%) translateX(-50%) scale(1);
          }
          100% {
            left: 100%;
            opacity: 0;
            transform: translateY(-50%) translateX(-50%) scale(0.8);
          }
        }

        @keyframes moveDotLeft {
          0% {
            right: 0%;
            opacity: 0;
            transform: translateY(-50%) translateX(50%) scale(0.8);
          }
          10% {
            opacity: 1;
            transform: translateY(-50%) translateX(50%) scale(1);
          }
          90% {
            opacity: 1;
            transform: translateY(-50%) translateX(50%) scale(1);
          }
          100% {
            right: 100%;
            opacity: 0;
            transform: translateY(-50%) translateX(50%) scale(0.8);
          }
        }
      `}</style>
    </div>
  );
};

export default PacketFlowDiagram;