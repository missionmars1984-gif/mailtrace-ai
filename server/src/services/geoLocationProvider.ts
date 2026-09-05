import type { GeoLocationData, IpClassificationType } from '../types/index.js';
import { DatabaseService } from '../db/database.js';
import net from 'node:net';

export interface IGeoLocationProvider {
  getLocation(ip: string): Promise<GeoLocationData>;
}

export class GeoLocationProvider implements IGeoLocationProvider {
  /**
   * Strictly classifies an IP address according to IETF RFC standards.
   * Classifications:
   * PUBLIC | PRIVATE | LOOPBACK | LINK_LOCAL | MULTICAST | DOCUMENTATION | RESERVED | UNSPECIFIED | INVALID
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

      // 0.0.0.0/8 (Current network / RFC 1122 / RFC 6890)
      if (p0 === 0) {
        return { isPrivate: true, type: 'UNSPECIFIED', reason: 'RFC 1122 Current Network / Unspecified' };
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
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 6890 IETF Protocol Assignments (192.0.0.0/24)' };
      }

      // 192.0.2.0/24 (TEST-NET-1 Documentation / RFC 5737)
      if (p0 === 192 && p1 === 0 && p2 === 2) {
        return { isPrivate: true, type: 'DOCUMENTATION', reason: 'RFC 5737 TEST-NET-1 Documentation (192.0.2.0/24)' };
      }

      // 192.88.99.0/24 (6to4 Relay Anycast / RFC 7526)
      if (p0 === 192 && p1 === 88 && p2 === 99) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 7526 6to4 Relay Anycast (192.88.99.0/24)' };
      }

      // 192.168.0.0/16 (Private-Use / RFC 1918)
      if (p0 === 192 && p1 === 168) {
        return { isPrivate: true, type: 'PRIVATE', reason: 'RFC 1918 Private Network (192.168.0.0/16)' };
      }

      // 198.18.0.0/15 (Benchmarking / RFC 2544)
      if (p0 === 198 && (p1 === 18 || p1 === 19)) {
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 2544 Benchmarking (198.18.0.0/15)' };
      }

      // 198.51.100.0/24 (TEST-NET-2 Documentation / RFC 5737)
      if (p0 === 198 && p1 === 51 && p2 === 100) {
        return { isPrivate: true, type: 'DOCUMENTATION', reason: 'RFC 5737 TEST-NET-2 Documentation (198.51.100.0/24)' };
      }

      // 203.0.113.0/24 (TEST-NET-3 Documentation / RFC 5737)
      if (p0 === 203 && p1 === 0 && p2 === 113) {
        return { isPrivate: true, type: 'DOCUMENTATION', reason: 'RFC 5737 TEST-NET-3 Documentation (203.0.113.0/24)' };
      }

      // 224.0.0.0/4 (Multicast / RFC 5771)
      if (p0 >= 224 && p0 <= 239) {
        return { isPrivate: true, type: 'MULTICAST', reason: 'RFC 5771 Multicast (224.0.0.0/4)' };
      }

      // 240.0.0.0/4 (Reserved for future use / RFC 1112)
      if (p0 >= 240 && p0 <= 255) {
        if (p0 === 255 && p1 === 255 && p2 === 255 && p3 === 255) {
          return { isPrivate: true, type: 'RESERVED', reason: 'RFC 919 Limited Broadcast (255.255.255.255)' };
        }
        return { isPrivate: true, type: 'RESERVED', reason: 'RFC 1112 Reserved / Future Use (240.0.0.0/4)' };
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
        return { isPrivate: true, type: 'UNSPECIFIED', reason: 'RFC 4291 IPv6 Unspecified (::)' };
      }

      // IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1 or ::ffff:203.0.113.1)
      if (clean.startsWith('::ffff:')) {
        const embeddedV4 = clean.substring(7);
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(embeddedV4)) {
          return this.isPrivateOrReserved(embeddedV4);
        }
      }

      // Multicast (ff00::/8 / RFC 4291)
      if (clean.startsWith('ff') && /^[0-9a-f:]+$/i.test(clean)) {
        return { isPrivate: true, type: 'MULTICAST', reason: 'RFC 4291 IPv6 Multicast (ff00::/8)' };
      }

      // Link-Local (fe80::/10 / RFC 4291)
      if (/^fe[89ab][0-9a-f]:/i.test(clean) || clean.startsWith('fe80:')) {
        return { isPrivate: true, type: 'LINK_LOCAL', reason: 'RFC 4291 IPv6 Link-Local (fe80::/10)' };
      }

      // Unique Local Address ULA / Private (fc00::/7 -> fc00::/8 or fd00::/8)
      if (/^f[cd][0-9a-f]{2}:/i.test(clean) || clean.startsWith('fc') || clean.startsWith('fd')) {
        return { isPrivate: true, type: 'PRIVATE', reason: 'RFC 4193 IPv6 Unique Local Address (fc00::/7)' };
      }

      // Documentation Prefix (2001:db8::/32 / RFC 3849)
      if (clean.startsWith('2001:db8:') || clean.startsWith('2001:0db8:')) {
        return { isPrivate: true, type: 'DOCUMENTATION', reason: 'RFC 3849 IPv6 Documentation (2001:db8::/32)' };
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
   * Non-public IPs are strictly labeled without external network queries.
   */
  async getLocation(ip: string): Promise<GeoLocationData> {
    if (!ip || !ip.trim()) {
      console.log(`[GeoIP] Extracted IP: None`);
      console.log(`[GeoIP] Classification: INVALID`);
      console.log(`[GeoIP] Lookup failure: Empty or missing IP`);
      console.log(`[GeoIP] Parsed country: Location unavailable — invalid IP`);
      console.log(`[GeoIP] Parsed city: N/A`);
      console.log(`[GeoIP] Parsed ASN: N/A`);
      console.log(`[GeoIP] Parsed coordinates: None`);

      return {
        ip: '',
        classification: 'INVALID',
        geoAvailable: false,
        country: 'Location unavailable — invalid IP',
        countryCode: undefined,
        region: undefined,
        city: undefined,
        latitude: undefined,
        longitude: undefined,
        lat: undefined,
        lon: undefined,
        timezone: undefined,
        asn: undefined,
        organization: undefined,
        org: undefined,
        isp: undefined,
        network: undefined,
        provider: undefined,
        error: 'Empty or missing IP',
        isPrivate: true,
        isPublic: false,
        location: null,
        reason: 'Empty or missing IP',
        ipType: 'INVALID',
        lookupStatus: 'unavailable',
        statusMessage: 'Location unavailable — invalid IP',
        source: 'rfc_boundary_filter',
      };
    }

    const cleanIp = ip.trim().replace(/^\[|\]$/g, '');
    const classification = GeoLocationProvider.isPrivateOrReserved(cleanIp);

    console.log(`[GeoIP] Extracted IP: ${cleanIp}`);
    console.log(`[GeoIP] Classification: ${classification.type}`);

    // CRITICAL RULE: ONLY an IP classified as PUBLIC may be sent to GeoIP.
    // Non-public IPs (PRIVATE, LOOPBACK, LINK_LOCAL, MULTICAST, DOCUMENTATION, RESERVED, UNSPECIFIED, INVALID)
    // bypass GeoIP completely.
    if (classification.type !== 'PUBLIC') {
      let reason = 'Non-public/reserved IP';
      let statusMsg = 'Location unavailable — non-public/reserved IP';

      if (classification.type === 'PRIVATE') {
        reason = 'Private/internal IP';
        statusMsg = 'Location unavailable — private/internal IP';
      } else if (classification.type === 'LOOPBACK') {
        reason = 'Non-public/reserved IP';
        statusMsg = 'Location unavailable — non-public/reserved IP';
      } else if (classification.type === 'LINK_LOCAL') {
        reason = 'Link-local IP';
        statusMsg = 'Location unavailable — link-local IP';
      } else if (classification.type === 'DOCUMENTATION') {
        reason = 'Documentation/test IP';
        statusMsg = 'Location unavailable — documentation/test IP';
      } else if (classification.type === 'MULTICAST') {
        reason = 'Multicast IP';
        statusMsg = 'Location unavailable — multicast IP';
      } else if (classification.type === 'UNSPECIFIED') {
        reason = 'Unspecified IP';
        statusMsg = 'Location unavailable — unspecified IP';
      } else if (classification.type === 'INVALID') {
        reason = 'Invalid IP';
        statusMsg = 'Location unavailable — invalid IP';
      }

      console.log(`[GeoIP] Parsed country: ${statusMsg}`);
      console.log(`[GeoIP] Parsed city: N/A`);
      console.log(`[GeoIP] Parsed ASN: N/A`);
      console.log(`[GeoIP] Parsed coordinates: None`);

      return {
        ip: cleanIp,
        classification: classification.type,
        geoAvailable: false,
        country: statusMsg,
        countryCode: undefined,
        region: undefined,
        city: undefined,
        latitude: undefined,
        longitude: undefined,
        lat: undefined,
        lon: undefined,
        timezone: undefined,
        asn: undefined,
        organization: undefined,
        org: undefined,
        isp: undefined,
        network: undefined,
        provider: undefined,
        error: undefined,
        isPrivate: true,
        isPublic: false,
        location: null,
        reason,
        ipType: classification.type,
        lookupStatus: classification.type === 'PRIVATE' ? 'private_ip' : 'unavailable',
        statusMessage: statusMsg,
        source: 'rfc_boundary_filter',
      };
    }

    // Public IP: Start lookup
    console.log(`[GeoIP] Public lookup started: ${cleanIp}`);

    // 1. Check if external GeoIP lookup is explicitly disabled
    if (process.env.DISABLE_GEOIP === 'true') {
      console.log(`[GeoIP] Provider response status: Disabled (DISABLE_GEOIP=true)`);
      console.log(`[GeoIP] Lookup failure: GeoIP lookup unavailable`);
      console.log(`[GeoIP] Parsed country: Location unavailable — GeoIP lookup unavailable`);
      console.log(`[GeoIP] Parsed city: N/A`);
      console.log(`[GeoIP] Parsed ASN: N/A`);
      console.log(`[GeoIP] Parsed coordinates: None`);

      return {
        ip: cleanIp,
        classification: 'PUBLIC',
        geoAvailable: false,
        country: 'Location unavailable — GeoIP lookup unavailable',
        countryCode: undefined,
        region: undefined,
        city: undefined,
        latitude: undefined,
        longitude: undefined,
        lat: undefined,
        lon: undefined,
        timezone: undefined,
        asn: undefined,
        organization: undefined,
        org: undefined,
        isp: undefined,
        network: undefined,
        provider: 'provider_disabled',
        error: 'GeoIP lookup disabled',
        isPrivate: false,
        isPublic: true,
        location: null,
        reason: 'GeoIP lookup unavailable',
        ipType: 'PUBLIC',
        lookupStatus: 'unavailable',
        statusMessage: 'Location unavailable — GeoIP lookup unavailable',
        source: 'provider_disabled',
      };
    }

    // 2. Check local SQLite cache first
    try {
      const cached = DatabaseService.getCachedGeoLocation(cleanIp);
      if (cached) {
        const hasValidCoords = cached.latitude !== undefined && cached.longitude !== undefined && !(cached.latitude === 0 && cached.longitude === 0);
        console.log(`[GeoIP] Provider response status: Cache hit (SQLite)`);
        console.log(`[GeoIP] Parsed country: ${cached.country}`);
        console.log(`[GeoIP] Parsed city: ${cached.city || 'N/A'}`);
        console.log(`[GeoIP] Parsed ASN: ${cached.asn || 'N/A'}`);
        console.log(`[GeoIP] Parsed coordinates: ${hasValidCoords ? `${cached.latitude}, ${cached.longitude}` : 'None'}`);

        return {
          ip: cleanIp,
          classification: 'PUBLIC',
          geoAvailable: hasValidCoords,
          country: cached.country,
          countryCode: cached.countryCode,
          region: cached.region,
          city: cached.city,
          latitude: cached.latitude ?? cached.lat,
          longitude: cached.longitude ?? cached.lon,
          lat: cached.latitude ?? cached.lat,
          lon: cached.longitude ?? cached.lon,
          timezone: cached.timezone,
          asn: cached.asn,
          organization: cached.organization ?? cached.org,
          org: cached.organization ?? cached.org,
          isp: cached.isp,
          network: cached.network,
          provider: cached.provider || 'sqlite_cache',
          error: undefined,
          isPrivate: false,
          isPublic: true,
          location: cached.location ?? (cached.city ? `${cached.city}, ${cached.country}` : cached.country),
          reason: undefined,
          ipType: 'PUBLIC',
          lookupStatus: cached.lookupStatus || 'resolved',
          statusMessage: cached.statusMessage || 'Resolved via live GeoIP provider',
          source: 'sqlite_cache',
        };
      }
    } catch {
      // Database cache read error - proceed to live lookup
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
        console.log(`[GeoIP] Provider response status: HTTP 429`);
        console.log(`[GeoIP] Lookup failure: Rate limit exceeded`);
        console.log(`[GeoIP] Parsed country: Location unavailable — GeoIP lookup unavailable`);
        console.log(`[GeoIP] Parsed city: N/A`);
        console.log(`[GeoIP] Parsed ASN: N/A`);
        console.log(`[GeoIP] Parsed coordinates: None`);

        return {
          ip: cleanIp,
          classification: 'PUBLIC',
          geoAvailable: false,
          country: 'Location unavailable — GeoIP lookup unavailable',
          countryCode: undefined,
          region: undefined,
          city: undefined,
          latitude: undefined,
          longitude: undefined,
          lat: undefined,
          lon: undefined,
          timezone: undefined,
          asn: undefined,
          organization: undefined,
          org: undefined,
          isp: undefined,
          network: undefined,
          provider: 'ip-api.com',
          error: 'Rate limit exceeded',
          isPrivate: false,
          isPublic: true,
          location: null,
          reason: 'GeoIP lookup unavailable',
          ipType: 'PUBLIC',
          lookupStatus: 'rate_limited',
          statusMessage: 'Location unavailable — GeoIP lookup unavailable',
          source: 'ip-api.com',
        };
      }

      if (res.ok) {
        const data = (await res.json()) as any;

        // Check provider-level error messages
        if (data && data.status === 'fail') {
          console.log(`[GeoIP] Provider response status: Fail (${data.message || 'unknown'})`);
          console.log(`[GeoIP] Lookup failure: ${data.message || 'Lookup failed'}`);
          console.log(`[GeoIP] Parsed country: Location unavailable — GeoIP lookup unavailable`);
          console.log(`[GeoIP] Parsed city: N/A`);
          console.log(`[GeoIP] Parsed ASN: N/A`);
          console.log(`[GeoIP] Parsed coordinates: None`);

          return {
            ip: cleanIp,
            classification: 'PUBLIC',
            geoAvailable: false,
            country: 'Location unavailable — GeoIP lookup unavailable',
            countryCode: undefined,
            region: undefined,
            city: undefined,
            latitude: undefined,
            longitude: undefined,
            lat: undefined,
            lon: undefined,
            timezone: undefined,
            asn: undefined,
            organization: undefined,
            org: undefined,
            isp: undefined,
            network: undefined,
            provider: 'ip-api.com',
            error: data.message || 'Provider lookup failed',
            isPrivate: false,
            isPublic: true,
            location: null,
            reason: 'GeoIP lookup unavailable',
            ipType: 'PUBLIC',
            lookupStatus: 'lookup_failed',
            statusMessage: 'Location unavailable — GeoIP lookup unavailable',
            source: 'ip-api.com',
          };
        }

        if (data && data.status === 'success') {
          const lat = typeof data.lat === 'number' && data.lat >= -90 && data.lat <= 90 ? data.lat : undefined;
          const lon = typeof data.lon === 'number' && data.lon >= -180 && data.lon <= 180 ? data.lon : undefined;
          const hasValidCoords = lat !== undefined && lon !== undefined && !(lat === 0 && lon === 0);
          const parsedAsn = data.as ? data.as.split(' ')[0] : undefined;

          console.log(`[GeoIP] Provider response status: HTTP 200 OK`);
          console.log(`[GeoIP] Parsed country: ${data.country || 'Unknown Jurisdiction'}`);
          console.log(`[GeoIP] Parsed city: ${data.city || 'N/A'}`);
          console.log(`[GeoIP] Parsed ASN: ${parsedAsn || 'N/A'}`);
          console.log(`[GeoIP] Parsed coordinates: ${hasValidCoords ? `${lat}, ${lon}` : 'None'}`);

          const geoResult: GeoLocationData = {
            ip: cleanIp,
            classification: 'PUBLIC',
            geoAvailable: hasValidCoords,
            country: data.country || 'Unknown Jurisdiction',
            countryCode: data.countryCode || undefined,
            region: data.regionName || data.country || undefined,
            city: data.city || undefined,
            latitude: lat,
            longitude: lon,
            lat,
            lon,
            timezone: data.timezone || undefined,
            asn: parsedAsn,
            organization: data.org || data.isp || undefined,
            org: data.org || data.isp || undefined,
            isp: data.isp || undefined,
            network: undefined,
            provider: 'ip-api.com',
            error: undefined,
            isPrivate: false,
            isPublic: true,
            location: data.country ? `${data.city ? data.city + ', ' : ''}${data.country}` : null,
            reason: undefined,
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
      const isTimeout = err.name === 'AbortError';
      console.log(`[GeoIP] Provider response status: Exception (${isTimeout ? 'Timeout' : err.message})`);
      console.log(`[GeoIP] Lookup failure: ${isTimeout ? 'Location lookup timed out after 4000ms' : err.message}`);
      console.log(`[GeoIP] Parsed country: Location unavailable — GeoIP lookup unavailable`);
      console.log(`[GeoIP] Parsed city: N/A`);
      console.log(`[GeoIP] Parsed ASN: N/A`);
      console.log(`[GeoIP] Parsed coordinates: None`);

      return {
        ip: cleanIp,
        classification: 'PUBLIC',
        geoAvailable: false,
        country: 'Location unavailable — GeoIP lookup unavailable',
        countryCode: undefined,
        region: undefined,
        city: undefined,
        latitude: undefined,
        longitude: undefined,
        lat: undefined,
        lon: undefined,
        timezone: undefined,
        asn: undefined,
        organization: undefined,
        org: undefined,
        isp: undefined,
        network: undefined,
        provider: 'ip-api.com',
        error: isTimeout ? 'Timeout' : err.message,
        isPrivate: false,
        isPublic: true,
        location: null,
        reason: 'GeoIP lookup unavailable',
        ipType: 'PUBLIC',
        lookupStatus: isTimeout ? 'timeout' : 'lookup_failed',
        statusMessage: 'Location unavailable — GeoIP lookup unavailable',
        source: isTimeout ? 'timeout' : 'lookup_failed',
      };
    }

    // 4. Return graceful unresolved public state without inventing coordinates
    console.log(`[GeoIP] Provider response status: Fallback Unresolved`);
    console.log(`[GeoIP] Lookup failure: Location lookup unavailable`);
    console.log(`[GeoIP] Parsed country: Location unavailable — GeoIP lookup unavailable`);
    console.log(`[GeoIP] Parsed city: N/A`);
    console.log(`[GeoIP] Parsed ASN: N/A`);
    console.log(`[GeoIP] Parsed coordinates: None`);

    return {
      ip: cleanIp,
      classification: 'PUBLIC',
      geoAvailable: false,
      country: 'Location unavailable — GeoIP lookup unavailable',
      countryCode: undefined,
      region: undefined,
      city: undefined,
      latitude: undefined,
      longitude: undefined,
      lat: undefined,
      lon: undefined,
      timezone: undefined,
      asn: undefined,
      organization: undefined,
      org: undefined,
      isp: undefined,
      network: undefined,
      provider: 'unresolved',
      error: 'Unresolved',
      isPrivate: false,
      isPublic: true,
      location: null,
      reason: 'GeoIP lookup unavailable',
      ipType: 'PUBLIC',
      lookupStatus: 'lookup_failed',
      statusMessage: 'Location unavailable — GeoIP lookup unavailable',
      source: 'unresolved',
    };
  }
}

export const geoProvider = new GeoLocationProvider();

