import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

interface HTTPRequest {
  id: number;
  timestamp: number;
  timestampMs: string;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  method: string;
  uri: string;
  host?: string;
  userAgent?: string;
  headers: Record<string, string>;
  payload: string;
  responseStatus?: number;
  responseTime?: number;
}

// Manual PCAP parser for HTTP requests
function parseHTTPFromPCAP(buffer: Buffer): HTTPRequest[] {
  const httpRequests: HTTPRequest[] = [];
  let offset = 0;

  // Read PCAP global header
  const magicNumber = buffer.readUInt32LE(offset);
  let littleEndian = true;
  
  if (magicNumber === 0xa1b2c3d4) {
    littleEndian = true;
  } else if (magicNumber === 0xd4c3b2a1) {
    littleEndian = false;
  } else if (magicNumber === 0xa1b23c4d) {
    littleEndian = true;
  } else if (magicNumber === 0x4d3cb2a1) {
    littleEndian = false;
  } else {
    throw new Error(`Invalid PCAP magic number: ${magicNumber.toString(16)}`);
  }

  const readUInt32 = littleEndian
    ? (buf: Buffer, off: number) => buf.readUInt32LE(off)
    : (buf: Buffer, off: number) => buf.readUInt32BE(off);

  const linkType = readUInt32(buffer, 20);
  offset += 24;

  let packetId = 0;
  const responseMap: Map<string, HTTPRequest> = new Map();

  while (offset + 16 <= buffer.length) {
    try {
      const timestampSec = readUInt32(buffer, offset);
      const timestampUsec = readUInt32(buffer, offset + 4);
      const capturedLength = readUInt32(buffer, offset + 8);
      
      offset += 16;

      if (offset + capturedLength > buffer.length) break;

      const packetData = buffer.slice(offset, offset + capturedLength);
      offset += capturedLength;

      packetId++;
      const timestamp = timestampSec + timestampUsec / 1000000;
      const date = new Date(timestamp * 1000);

      const httpData = extractHTTPData(packetData, linkType, packetId, timestamp, date);
      if (httpData) {
        if (httpData.method) {
          httpRequests.push(httpData);
          // Store for response matching
          const key = `${httpData.srcIP}:${httpData.srcPort}-${httpData.dstIP}:${httpData.dstPort}`;
          responseMap.set(key, httpData);
        } else if (httpData.responseStatus && responseMap.size > 0) {
          // Try to match with request
          const key = `${httpData.dstIP}:${httpData.dstPort}-${httpData.srcIP}:${httpData.srcPort}`;
          const request = responseMap.get(key);
          if (request) {
            request.responseStatus = httpData.responseStatus;
            request.responseTime = timestamp - request.timestamp;
            responseMap.delete(key);
          }
        }
      }
    } catch (error) {
      console.error('Error parsing packet:', error);
      break;
    }
  }

  return httpRequests;
}

function extractHTTPData(
  data: Buffer,
  linkType: number,
  packetId: number,
  timestamp: number,
  date: Date
): HTTPRequest | null {
  try {
    let offset = 0;

    // Skip link layer header
    if (linkType === 113) {
      offset += 16; // Linux SLL
    } else {
      offset += 14; // Ethernet
    }

    // Check for IPv4
    if (offset + 20 > data.length) return null;
    const etherType = linkType === 113 ? data.readUInt16BE(14) : data.readUInt16BE(12);
    if (etherType !== 0x0800) return null;

    const ipHeaderLength = (data[offset] & 0x0F) * 4;
    const ipProtocol = data[offset + 9];
    
    if (ipProtocol !== 6) return null; // Not TCP

    const srcIP = Array.from(data.slice(offset + 12, offset + 16)).join('.');
    const dstIP = Array.from(data.slice(offset + 16, offset + 20)).join('.');
    
    offset += ipHeaderLength;

    if (offset + 20 > data.length) return null;

    const srcPort = data.readUInt16BE(offset);
    const dstPort = data.readUInt16BE(offset + 2);
    const tcpHeaderLength = ((data[offset + 12] >> 4) & 0x0F) * 4;
    
    offset += tcpHeaderLength;

    if (offset >= data.length) return null;

    const payloadData = data.slice(offset);
    let payload = '';
    
    try {
      payload = payloadData.toString('utf8');
    } catch {
      return null;
    }

    // Check for HTTP request
    const httpRequestMatch = payload.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) ([^\s]+) HTTP\/(\d\.\d)/);
    if (httpRequestMatch) {
      const method = httpRequestMatch[1];
      const uri = httpRequestMatch[2];
      const headers: Record<string, string> = {};
      
      const headerLines = payload.split('\r\n');
      for (let i = 1; i < headerLines.length; i++) {
        const line = headerLines[i];
        if (line === '') break;
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
          const headerName = line.substring(0, colonIndex).trim();
          const headerValue = line.substring(colonIndex + 1).trim();
          headers[headerName] = headerValue;
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
        method,
        uri,
        host: headers['Host'],
        userAgent: headers['User-Agent'],
        headers,
        payload: payload.substring(0, 2000)
      };
    }

    // Check for HTTP response
    const httpResponseMatch = payload.match(/^HTTP\/(\d\.\d) (\d+) (.+)/);
    if (httpResponseMatch) {
      const status = parseInt(httpResponseMatch[2]);
      
      return {
        id: packetId,
        timestamp,
        timestampMs: date.toISOString(),
        srcIP,
        dstIP,
        srcPort,
        dstPort,
        method: '',
        uri: '',
        headers: {},
        payload: payload.substring(0, 2000),
        responseStatus: status
      };
    }

    return null;
  } catch (error) {
    return null;
  }
}

export async function GET(request: NextRequest) {
  try {
    const publicDir = path.join(process.cwd(), 'public');
    
    // Find the first .pcap file in the public directory
    const files = fs.readdirSync(publicDir);
    const pcapFile = files.find(file => file.endsWith('.pcap'));
    
    if (!pcapFile) {
      return NextResponse.json({ error: 'No PCAP file found in public directory' }, { status: 404 });
    }
    
    const pcapFilePath = path.join(publicDir, pcapFile);
    const buffer = fs.readFileSync(pcapFilePath);
    const httpRequests = parseHTTPFromPCAP(buffer);

    // Analyze HTTP requests
    const summary = {
      totalRequests: httpRequests.length,
      methods: [...new Set(httpRequests.map(r => r.method))].filter(m => m),
      uniqueHosts: [...new Set(httpRequests.map(r => r.host))].filter(h => h),
      uniqueURIs: [...new Set(httpRequests.map(r => r.uri))].filter(u => u),
      statusCodes: httpRequests
        .filter(r => r.responseStatus)
        .reduce((acc, r) => {
          const code = r.responseStatus!;
          acc[code] = (acc[code] || 0) + 1;
          return acc;
        }, {} as Record<number, number>),
      metadataRequests: httpRequests.filter(r => r.uri.includes('meta-data')).length,
      suspiciousPatterns: {
        awsMetadata: httpRequests.filter(r => r.uri.includes('169.254.169.254')).length,
        metadataAPI: httpRequests.filter(r => r.uri.includes('meta-data') || r.uri.includes('metadata')).length,
        cloudInit: httpRequests.filter(r => r.uri.includes('user-data')).length
      }
    };

    return NextResponse.json({
      requests: httpRequests,
      summary
    });
  } catch (error: any) {
    console.error('Error:', error);
    return NextResponse.json({
      error: 'Internal server error',
      details: error.message
    }, { status: 500 });
  }
}
