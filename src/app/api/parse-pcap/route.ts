import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

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

// Manual PCAP parser that handles both byte orders
function parsePCAP(buffer: Buffer): PacketData[] {
  const packets: PacketData[] = [];
  let offset = 0;

  // Read PCAP global header
  const magicNumber = buffer.readUInt32LE(offset);
  let littleEndian = true;
  
  if (magicNumber === 0xa1b2c3d4) {
    littleEndian = true;
  } else if (magicNumber === 0xd4c3b2a1) {
    littleEndian = false;
  } else if (magicNumber === 0xa1b23c4d) {
    // Nanosecond resolution
    littleEndian = true;
  } else if (magicNumber === 0x4d3cb2a1) {
    // Nanosecond resolution, big endian
    littleEndian = false;
  } else {
    throw new Error(`Invalid PCAP magic number: ${magicNumber.toString(16)}`);
  }

  const readUInt16 = littleEndian 
    ? (buf: Buffer, off: number) => buf.readUInt16LE(off)
    : (buf: Buffer, off: number) => buf.readUInt16BE(off);
  
  const readUInt32 = littleEndian
    ? (buf: Buffer, off: number) => buf.readUInt32LE(off)
    : (buf: Buffer, off: number) => buf.readUInt32BE(off);

  // Read link layer type
  const linkType = readUInt32(buffer, 20);
  console.log('Link layer type:', linkType);

  offset += 24; // Skip global header

  let packetId = 0;

  // Read packets
  while (offset + 16 <= buffer.length) {
    try {
      // Read packet header
      const timestampSec = readUInt32(buffer, offset);
      const timestampUsec = readUInt32(buffer, offset + 4);
      const capturedLength = readUInt32(buffer, offset + 8);
      const originalLength = readUInt32(buffer, offset + 12);
      
      offset += 16;

      if (offset + capturedLength > buffer.length) {
        break;
      }

      const packetData = buffer.slice(offset, offset + capturedLength);
      offset += capturedLength;

      packetId++;
      const timestamp = timestampSec + timestampUsec / 1000000;
      const date = new Date(timestamp * 1000);

      // Parse packet with link type info
      const parsed = parsePacketData(packetData, packetId, timestamp, date, capturedLength, linkType);
      if (parsed) {
        packets.push(parsed);
      }

      // No limit - parse all packets
    } catch (error) {
      console.error('Error parsing packet:', error);
      break;
    }
  }

  return packets;
}

function parsePacketData(
  data: Buffer, 
  packetId: number, 
  timestamp: number, 
  date: Date, 
  length: number,
  linkType: number = 1 // Default to Ethernet
): PacketData | null {
  try {
    let offset = 0;
    let srcMac = '';
    let dstMac = '';
    let etherType = 0;

    // Handle different link layer types
    if (linkType === 113) {
      // LINKTYPE_LINUX_SLL (Linux cooked capture)
      // Structure:
      // 0-1: Packet type (2 bytes)
      // 2-3: ARPHRD type (2 bytes)
      // 4-5: Link-layer address length (2 bytes)
      // 6-13: Link-layer address (8 bytes, padded)
      // 14-15: Protocol type (2 bytes)
      
      const packetType = data.readUInt16BE(offset);
      offset += 2;
      const arphrdType = data.readUInt16BE(offset);
      offset += 2;
      const llAddrLen = data.readUInt16BE(offset);
      offset += 2;
      
      // Read source MAC (up to llAddrLen bytes, but field is 8 bytes)
      if (llAddrLen > 0 && llAddrLen <= 8) {
        srcMac = data.slice(offset, offset + llAddrLen).toString('hex').match(/.{2}/g)?.join(':') || '';
      }
      offset += 8; // Skip the entire 8-byte address field
      
      etherType = data.readUInt16BE(offset);
      offset += 2;
      
      dstMac = 'N/A'; // Not available in Linux SLL
    } else {
      // LINKTYPE_ETHERNET (1) - Standard Ethernet
      dstMac = data.slice(offset, offset + 6).toString('hex').match(/.{2}/g)?.join(':') || '';
      offset += 6;
      srcMac = data.slice(offset, offset + 6).toString('hex').match(/.{2}/g)?.join(':') || '';
      offset += 6;
      etherType = data.readUInt16BE(offset);
      offset += 2;
    }

    let protocol = 'Unknown';
    let srcIP = '';
    let dstIP = '';
    let srcPort = 0;
    let dstPort = 0;
    let payload = '';
    let info = '';
    let tcpFlags: string[] = [];
    let httpMethod = '';
    let httpPath = '';
    let httpStatus = 0;
    let httpHeaders: Record<string, string> = {};

    // Check if it's IPv4
    if (etherType === 0x0800 && offset + 20 <= data.length) {
      // Parse IPv4 header
      const ipHeaderLength = (data[offset] & 0x0F) * 4;
      const ipProtocol = data[offset + 9];
      
      srcIP = Array.from(data.slice(offset + 12, offset + 16)).join('.');
      dstIP = Array.from(data.slice(offset + 16, offset + 20)).join('.');
      
      offset += ipHeaderLength;

      // TCP Protocol
      if (ipProtocol === 6 && offset + 20 <= data.length) {
        protocol = 'TCP';
        srcPort = data.readUInt16BE(offset);
        dstPort = data.readUInt16BE(offset + 2);
        
        // TCP flags
        const tcpFlagsByte = data[offset + 13];
        if (tcpFlagsByte & 0x01) tcpFlags.push('FIN');
        if (tcpFlagsByte & 0x02) tcpFlags.push('SYN');
        if (tcpFlagsByte & 0x04) tcpFlags.push('RST');
        if (tcpFlagsByte & 0x08) tcpFlags.push('PSH');
        if (tcpFlagsByte & 0x10) tcpFlags.push('ACK');
        if (tcpFlagsByte & 0x20) tcpFlags.push('URG');
        
        const tcpHeaderLength = ((data[offset + 12] >> 4) & 0x0F) * 4;
        offset += tcpHeaderLength;

        // Try to parse HTTP
        if (offset < data.length) {
          const payloadData = data.slice(offset);
          try {
            payload = payloadData.toString('utf8', 0, Math.min(500, payloadData.length));
            
            // Check for HTTP
            const httpMatch = payload.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^\s]+) HTTP\/(\d\.\d)/);
            if (httpMatch) {
              httpMethod = httpMatch[1];
              httpPath = httpMatch[2];
              protocol = 'HTTP';
              
              // Parse HTTP headers
              const headerLines = payload.split('\r\n');
              for (let i = 1; i < headerLines.length; i++) {
                const line = headerLines[i];
                if (line === '') break;
                const colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                  const headerName = line.substring(0, colonIndex).trim();
                  const headerValue = line.substring(colonIndex + 1).trim();
                  httpHeaders[headerName] = headerValue;
                }
              }
              info = `${httpMethod} ${httpPath}`;
            } else {
              const httpResponseMatch = payload.match(/^HTTP\/(\d\.\d) (\d+) (.+)/);
              if (httpResponseMatch) {
                httpStatus = parseInt(httpResponseMatch[2]);
                protocol = 'HTTP';
                info = `HTTP ${httpStatus} ${httpResponseMatch[3]}`;
                
                // Parse response headers
                const headerLines = payload.split('\r\n');
                for (let i = 1; i < headerLines.length; i++) {
                  const line = headerLines[i];
                  if (line === '') break;
                  const colonIndex = line.indexOf(':');
                  if (colonIndex > 0) {
                    const headerName = line.substring(0, colonIndex).trim();
                    const headerValue = line.substring(colonIndex + 1).trim();
                    httpHeaders[headerName] = headerValue;
                  }
                }
              } else {
                info = `${srcPort} → ${dstPort} [${tcpFlags.join(', ')}]`;
              }
            }
          } catch {
            // Non-UTF8 payload
            payload = payloadData.toString('hex', 0, Math.min(100, payloadData.length));
            info = `${srcPort} → ${dstPort} [${tcpFlags.join(', ')}]`;
          }
        } else {
          info = `${srcPort} → ${dstPort} [${tcpFlags.join(', ')}]`;
        }
      }
      // UDP Protocol
      else if (ipProtocol === 17 && offset + 8 <= data.length) {
        protocol = 'UDP';
        srcPort = data.readUInt16BE(offset);
        dstPort = data.readUInt16BE(offset + 2);
        offset += 8;
        
        if (offset < data.length) {
          const payloadData = data.slice(offset);
          try {
            payload = payloadData.toString('utf8', 0, Math.min(500, payloadData.length));
          } catch {
            payload = payloadData.toString('hex', 0, Math.min(100, payloadData.length));
          }
        }
        info = `${srcPort} → ${dstPort}`;
      }
      // ICMP Protocol
      else if (ipProtocol === 1 && offset + 2 <= data.length) {
        protocol = 'ICMP';
        const icmpType = data[offset];
        const icmpCode = data[offset + 1];
        info = `Type: ${icmpType}, Code: ${icmpCode}`;
      }
    }

    return {
      id: packetId,
      timestamp,
      timestampMs: date.toISOString(),
      srcIP,
      dstIP,
      srcPort,
      dstPort,
      protocol,
      length,
      info,
      payload: payload.substring(0, 500),
      headers: {
        srcMac,
        dstMac,
        etherType: `0x${etherType.toString(16).padStart(4, '0')}`
      },
      tcpFlags: tcpFlags.length > 0 ? tcpFlags : undefined,
      httpMethod: httpMethod || undefined,
      httpPath: httpPath || undefined,
      httpStatus: httpStatus || undefined,
      httpHeaders: Object.keys(httpHeaders).length > 0 ? httpHeaders : undefined
    };
  } catch (error) {
    console.error('Error parsing packet data:', error);
    return null;
  }
}

const DEFAULT_PACKET_LIMIT = 2000;
const MAX_PACKET_LIMIT = 10000;

export async function GET(request: NextRequest) {
  try {
    const pcapFilePath = path.join(process.cwd(), 'public', 'capture_%Y%m%d_%H%M%S_00001_20251023142449.pcap');
    
    if (!fs.existsSync(pcapFilePath)) {
      return NextResponse.json({ error: 'PCAP file not found' }, { status: 404 });
    }

    // Read the entire PCAP file
    const buffer = fs.readFileSync(pcapFilePath);
    
    // Parse packets
    const packets = parsePCAP(buffer);

    // Generate summary
    const summary = {
      totalPackets: packets.length,
      protocols: [...new Set(packets.map(p => p.protocol))],
      uniqueIPs: [...new Set([...packets.map(p => p.srcIP), ...packets.map(p => p.dstIP)])].filter(ip => ip),
      httpRequests: packets.filter(p => p.httpMethod).length,
      httpResponses: packets.filter(p => p.httpStatus).length
    };

    let packetLimit = DEFAULT_PACKET_LIMIT;
    const limitParam = request.nextUrl.searchParams.get('limit');
    if (limitParam) {
      const parsedLimit = parseInt(limitParam, 10);
      if (!Number.isNaN(parsedLimit) && parsedLimit > 0) {
        packetLimit = Math.min(parsedLimit, MAX_PACKET_LIMIT);
      }
    }

    const truncated = packets.length > packetLimit;
    const limitedPackets = truncated ? packets.slice(0, packetLimit) : packets;

    return NextResponse.json({ 
      packets: limitedPackets,
      summary,
      meta: {
        totalPackets: packets.length,
        returnedPackets: limitedPackets.length,
        limit: packetLimit,
        truncated
      }
    });
  } catch (error: any) {
    console.error('Error:', error);
    return NextResponse.json({ 
      error: 'Internal server error', 
      details: error.message,
      stack: error.stack 
    }, { status: 500 });
  }
}
