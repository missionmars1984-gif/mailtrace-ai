import type { GeoLocationData, IpClassificationType } from '../types/index.js';
import { DatabaseService } from '../db/database.js';
import net from 'node:net';

export interface IGeoLocationProvider {
  getLocation(ip: string): Promise<GeoLocationData>;
}

export class GeoLocationProvider implements IGeoLocationProvider {
  /**
   * Strictly classifies an IP address according to IETF RFC standards.
   * Classifies as: PUBLIC | PRIVATE | LOOPBACK | LINK_LOCAL | RESERVED | INVALID
   */
  static isPrivateOrReserved(ip: string): { isPrivate: boolean; type: IpClassificationType; reason?: string } {
    if (!ip || typeof ip !== 'string') {
      return { isPrivate: true, type: 'INVALID', reason: 'Empty or missing IP' };
    }

    // Clean IP: strip brackets [ ], leading/trailing whitespace
    let clean = ip.trim().replace(/^\[|\]$/g, '').toLowerCase();

    // Strip IPv6 prefix if present (e.g., "ipv6:2001:db8::1" -> "2001:db8::1")
    if (clean.startsWith('ipv6:')) {
      clean = clean.substring(5).trim();
    }

    // Strip port if IPv4 (e.g. 192.168.1.1:25)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(clean)) {
      clean = clean.split(':')[0];
    }

    const ipVersion = net.isIP(clean);
    if (ipVersion === 0) {
      return { isPrivate: true, type: 'INVALID', reason: 'Invalid IP address syntax' };
    }

    // 1. IPv4 Classification
    const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4Match) {
      const p0 = parseInt(ipv4Match[1], 10);
      const p1 = parseInt(ipv4Match[2], 10);
      const p2 = parseInt(ipv4Match[3], 10);
      const p3 = parseInt(ipv4Match[4], 10);

      // Verify valid octets (0-255)
      if (p0 > 255 || p1 > 255 || p2 > 255 || p3 > 255) {
        return { isPrivate: true, type: 'INVALID', reason: 'Octet value exceeds 255' };
      }

      // 0.0.0.0/8 (Current network / RFC 1122)
      if (p0 === 0) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 1122 Current Network' };
      }

      // 10.0.0.0/8 (Private-Use / RFC 1918)
      if (p0 === 10) {
        return { isPrivate: true, type: 'PRIVATE', reason: 'RFC 1918 Private Network (10.0.0.0/8)' };
      }

      // 100.64.0.0/10 (Shared Address Space / CGNAT / RFC 6598)
      if (p0 === 100 && p1 >= 64 && p1 <= 127) {
        return { isPrivate: true, type: 'PRIVATE', reason: 'RFC 6598 Carrier-Grade NAT (100.64.0.0/10)' };
      }

      // 127.0.0.0/8 (Loopback / RFC 1122)
      if (p0 === 127) {
        return { isPrivate: true, type: 'LOOPBACK', reason: 'RFC 1122 Loopback (127.0.0.0/8)' };
      }

      // 169.254.0.0/16 (Link-Local / RFC 3927)
      if (p0 === 169 && p1 === 254) {
        return { isPrivate: true, type: 'LINK_LOCAL', reason: 'RFC 3927 Link-Local (169.254.0.0/16)' };
      }

      // 172.16.0.0/12 (Private-Use / RFC 1918)
      if (p0 === 172 && p1 >= 16 && p1 <= 31) {
        return { isPrivate: true, type: 'PRIVATE', reason: 'RFC 1918 Private Network (172.16.0.0/12)' };
      }

      // 192.0.0.0/24 (IETF Protocol Assignments / RFC 6890)
      if (p0 === 192 && p1 === 0 && p2 === 0) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 6890 IETF Protocol Assignments' };
      }

      // 192.0.2.0/24 (TEST-NET-1 / Documentation / RFC 5737)
      if (p0 === 192 && p1 === 0 && p2 === 2) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 5737 TEST-NET-1 Documentation' };
      }

      // 192.168.0.0/16 (Private-Use / RFC 1918)
      if (p0 === 192 && p1 === 168) {
        return { isPrivate: true, type: 'PRIVATE', reason: 'RFC 1918 Private Network (192.168.0.0/16)' };
      }

      // 198.18.0.0/15 (Network Interconnect Benchmark Testing / RFC 2544)
      if (p0 === 198 && (p1 === 18 || p1 === 19)) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 2544 Benchmark Testing' };
      }

      // 198.51.100.0/24 (TEST-NET-2 / Documentation / RFC 5737)
      if (p0 === 198 && p1 === 51 && p2 === 100) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 5737 TEST-NET-2 Documentation' };
      }

      // 203.0.113.0/24 (TEST-NET-3 / Documentation / RFC 5737)
      if (p0 === 203 && p1 === 0 && p2 === 113) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 5737 TEST-NET-3 Documentation' };
      }

      // 224.0.0.0/4 (Multicast / RFC 5771)
      if (p0 >= 224 && p0 <= 239) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 5771 Multicast' };
      }

      // 240.0.0.0/4 (Reserved for future use / RFC 1112)
      if (p0 >= 240 && p0 <= 255) {
        if (p0 === 255 && p1 === 255 && p2 === 255 && p3 === 255) {
          return { isPrivate: true, type: 'RESERVED', reason: 'RFC 919 Limited Broadcast' };
        }
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 1112 Reserved / Future Use' };
      }

      return { isPrivate: false, type: 'PUBLIC' };
    }

    // 2. IPv6 Classification
    if (clean.includes(':')) {
      // Loopback (::1)
      if (clean === '::1' || clean === '0:0:0:0:0:0:0:1') {
        return { isPrivate: true, type: 'LOOPBACK', reason: 'RFC 4291 IPv6 Loopback (::1)' };
      }

      // Unspecified (::)
      if (clean === '::' || clean === '0:0:0:0:0:0:0:0') {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 4291 IPv6 Unspecified (::)' };
      }

      // IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1 or ::ffff:203.0.113.1)
      if (clean.startsWith('::ffff:')) {
        const embeddedV4 = clean.substring(7);
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(embeddedV4)) {
          return this.isPrivateOrReserved(embeddedV4);
        }
      }

      // Link-Local (fe80::/10)
      if (/^fe[89ab][0-9a-f]:/i.test(clean) || clean.startsWith('fe80:')) {
        return { isPrivate: true, type: 'LINK_LOCAL', reason: 'RFC 4291 IPv6 Link-Local (fe80::/10)' };
      }

      // Unique Local Address ULA / Private (fc00::/7 -> fc00::/8 or fd00::/8)
      if (/^f[cd][0-9a-f]{2}:/i.test(clean) || clean.startsWith('fc') || clean.startsWith('fd')) {
        return { isPrivate: true, type: 'PRIVATE', reason: 'RFC 4193 IPv6 Unique Local Address (fc00::/7)' };
      }

      // Documentation Prefix (2001:db8::/32 / RFC 3849)
      if (clean.startsWith('2001:db8:') || clean.startsWith('2001:0db8:')) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 3849 IPv6 Documentation (2001:db8::/32)' };
      }

      // Check standard IPv6 hex character validity
      if (/^[0-9a-f:]+$/i.test(clean)) {
        return { isPrivate: false, type: 'PUBLIC' };
      }
    }

    return { isPrivate: true, type: 'INVALID', reason: 'Unrecognized IP format' };
  }

  /**
   * Resolves geolocation for an IP address.
   * Public IPs are looked up via live GeoIP provider (or local SQLite cache).
   * Non-public IPs are strictly labeled without inventing coordinates.
   */
  async getLocation(ip: string): Promise<GeoLocationData> {
    if (!ip || !ip.trim()) {
      return {
        country: 'No routable IPs found',
        region: 'Unassigned',
        city: 'Unresolved',
        isPrivate: true,
        ipType: 'INVALID',
        lookupStatus: 'unavailable',
        statusMessage: 'No routable IPs found in transport headers.',
        source: 'parser',
      };
    }

    const cleanIp = ip.trim().replace(/^\[|\]$/g, '');
    const classification = GeoLocationProvider.isPrivateOrReserved(cleanIp);

    // Non-public IPs are strictly handled without external network calls
    if (classification.isPrivate) {
      if (classification.type === 'PRIVATE' || classification.type === 'LOOPBACK' || classification.type === 'LINK_LOCAL') {
        return {
          ip: cleanIp,
          country: 'Geolocation unavailable — private/internal IP',
          countryCode: 'INT',
          region: classification.type === 'LOOPBACK' ? 'Loopback Interface' : 'Internal Corporate Subnet',
          city: classification.type === 'LOOPBACK' ? 'Loopback RFC 5735' : 'Private RFC 1918',
          lat: undefined,
          lon: undefined,
          asn: classification.type === 'LOOPBACK' ? 'RFC5735' : 'RFC1918',
          org: 'Internal Network Infrastructure',
          isp: 'Local / Non-Public Network',
          isPrivate: true,
          ipType: classification.type,
          lookupStatus: 'private_ip',
          statusMessage: 'Geolocation unavailable — private/internal IP',
          source: 'rfc_boundary_filter',
        };
      }

      if (classification.type === 'RESERVED') {
        return {
          ip: cleanIp,
          country: 'Geolocation unavailable — non-routable / reserved IP',
          countryCode: 'RES',
          region: 'Reserved Network',
          city: 'Reserved IANA / RFC 5737',
          lat: undefined,
          lon: undefined,
          asn: 'RFC5737',
          org: 'Reserved / Documentation Address Block',
          isp: 'Non-Routable Allocation',
          isPrivate: true,
          ipType: 'RESERVED',
          lookupStatus: 'unavailable',
          statusMessage: 'Geolocation unavailable — non-routable / reserved IP',
          source: 'rfc_boundary_filter',
        };
      }

      return {
        ip: cleanIp,
        country: 'Invalid IP address format',
        countryCode: 'INV',
        region: 'Invalid',
        city: 'Invalid',
        lat: undefined,
        lon: undefined,
        isPrivate: true,
        ipType: 'INVALID',
        lookupStatus: 'unavailable',
        statusMessage: 'Unparseable or malformed IP string',
        source: 'rfc_boundary_filter',
      };
    }

    // 1. Check local SQLite cache first
    try {
      const cached = DatabaseService.getCachedGeoLocation(cleanIp);
      if (cached) {
        return cached;
      }
    } catch {
      // Database cache read error - proceed to live lookup
    }

    // 2. Check if external GeoIP lookup is explicitly disabled
    if (process.env.DISABLE_GEOIP === 'true') {
      return {
        ip: cleanIp,
        country: 'Location lookup unavailable',
        region: 'Unresolved',
        city: 'Unresolved',
        isPrivate: false,
        ipType: 'PUBLIC',
        lookupStatus: 'unavailable',
        statusMessage: 'GeoIP enrichment unavailable — configure a GeoIP provider.',
        source: 'provider_disabled',
      };
    }

    // 3. Fetch live data from real GeoIP service
    // Uses ip-api.com free tier with strict 4000ms timeout
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);

      const apiUrl = process.env.GEOIP_API_URL
        ? `${process.env.GEOIP_API_URL.replace(/\/$/, '')}/${encodeURIComponent(cleanIp)}`
        : `http://ip-api.com/json/${encodeURIComponent(cleanIp)}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query`;

      const headers: Record<string, string> = {
        'User-Agent': 'MailTrace-AI-Forensics/1.0',
      };
      if (process.env.GEOIP_API_KEY) {
        headers['Authorization'] = `Bearer ${process.env.GEOIP_API_KEY}`;
      }

      const res = await fetch(apiUrl, {
        signal: controller.signal,
        headers,
      });
      clearTimeout(timeout);

      // Handle HTTP Rate Limiting
      if (res.status === 429) {
        return {
          ip: cleanIp,
          country: 'GeoIP service rate limited',
          region: 'Unresolved',
          city: 'Unresolved',
          isPrivate: false,
          ipType: 'PUBLIC',
          lookupStatus: 'rate_limited',
          statusMessage: 'GeoIP service rate limited',
          source: 'ip-api.com',
        };
      }

      if (res.ok) {
        const data = (await res.json()) as any;

        // Check provider-level rate limiting or error messages
        if (data && data.status === 'fail') {
          const msg = (data.message || '').toLowerCase();
          if (msg.includes('rate limit') || msg.includes('user_rate_limited')) {
            return {
              ip: cleanIp,
              country: 'GeoIP service rate limited',
              region: 'Unresolved',
              city: 'Unresolved',
              isPrivate: false,
              ipType: 'PUBLIC',
              lookupStatus: 'rate_limited',
              statusMessage: 'GeoIP service rate limited',
              source: 'ip-api.com',
            };
          }
          if (msg.includes('private') || msg.includes('reserved')) {
            return {
              ip: cleanIp,
              country: 'Geolocation unavailable — private/internal IP',
              region: 'Internal Network',
              city: 'Private / Non-Public',
              isPrivate: true,
              ipType: 'PRIVATE',
              lookupStatus: 'private_ip',
              statusMessage: 'Geolocation unavailable — private/internal IP',
              source: 'ip-api.com',
            };
          }
          return {
            ip: cleanIp,
            country: 'Location lookup unavailable',
            region: 'Unresolved',
            city: 'Unresolved',
            isPrivate: false,
            ipType: 'PUBLIC',
            lookupStatus: 'lookup_failed',
            statusMessage: `GeoIP lookup failed: ${data.message || 'unknown error'}`,
            source: 'ip-api.com',
          };
        }

        if (data && data.status === 'success') {
          const geoResult: GeoLocationData = {
            ip: cleanIp,
            country: data.country || 'Unknown Jurisdiction',
            countryCode: data.countryCode,
            region: data.regionName || data.country,
            city: data.city || 'Unknown City',
            lat: typeof data.lat === 'number' ? data.lat : undefined,
            lon: typeof data.lon === 'number' ? data.lon : undefined,
            timezone: data.timezone,
            isp: data.isp,
            org: data.org || data.isp,
            asn: data.as ? data.as.split(' ')[0] : undefined,
            isPrivate: false,
            ipType: 'PUBLIC',
            lookupStatus: 'resolved',
            statusMessage: 'Resolved via live GeoIP provider',
            source: 'ip-api.com',
          };

          // Cache in SQLite database
          try {
            DatabaseService.cacheGeoLocation(cleanIp, geoResult);
          } catch (cacheErr) {
            console.warn(`[GeoLocationProvider] Cache write warning for ${cleanIp}:`, cacheErr);
          }

          return geoResult;
        }
      }
    } catch (err: any) {
      if (err.name === 'AbortError') {
        return {
          ip: cleanIp,
          country: 'Location lookup timed out',
          region: 'Unresolved',
          city: 'Unresolved',
          isPrivate: false,
          ipType: 'PUBLIC',
          lookupStatus: 'timeout',
          statusMessage: 'Location lookup timed out after 4000ms',
          source: 'ip-api.com',
        };
      }
      console.warn(`[GeoLocationProvider] Live GeoIP lookup failed for ${cleanIp}: ${err.message}`);
    }

    // 4. Return graceful unresolved public state without inventing coordinates
    return {
      ip: cleanIp,
      country: 'Location lookup unavailable',
      countryCode: undefined,
      region: 'Unresolved',
      city: 'Unresolved',
      isPrivate: false,
      ipType: 'PUBLIC',
      lat: undefined,
      lon: undefined,
      asn: undefined,
      org: undefined,
      isp: undefined,
      lookupStatus: 'lookup_failed',
      statusMessage: 'Location lookup unavailable',
      source: 'unresolved',
    };
  }
}

export const geoProvider = new GeoLocationProvider();
