import type { GeoLocationData, IpClassificationType } from '../types/index.js';
import { DatabaseService } from '../db/database.js';
import net from 'node:net';

export interface IGeoLocationProvider {
  getLocation(ip: string): Promise<GeoLocationData>;
}

export class GeoLocationProvider implements IGeoLocationProvider {
  /**
   * Normalizes an IP string:
   * - strips leading/trailing whitespace
   * - strips surrounding brackets `[` and `]`
   * - strips case-insensitive `ipv6:` prefix
   * - strips IPv4 port number if present (e.g., "192.168.1.1:25")
   * - converts to lowercase
   */
  static normalizeIp(ip: string): string {
    if (!ip || typeof ip !== 'string') return '';
    let clean = ip.trim().replace(/^\[|\]$/g, '').toLowerCase();
    if (clean.startsWith('ipv6:')) {
      clean = clean.substring(5).trim();
    }
    // Strip port for IPv4 (e.g. 1.2.3.4:80)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(clean)) {
      clean = clean.split(':')[0];
    }
    return clean;
  }

  /**
   * Validates whether a candidate string is a syntactically valid IPv4 or IPv6 address.
   */
  static isValidIp(ip: string): boolean {
    const clean = this.normalizeIp(ip);
    return net.isIP(clean) !== 0;
  }

  /**
   * Strictly classifies an IP address according to IETF RFC standards.
   * Possible states:
   * PUBLIC | PRIVATE | LOOPBACK | LINK_LOCAL | MULTICAST | DOCUMENTATION | RESERVED | UNSPECIFIED | INVALID
   */
  static isPrivateOrReserved(ip: string): { isPrivate: boolean; type: IpClassificationType; reason?: string } {
    const clean = this.normalizeIp(ip);
    if (!clean) {
      return { isPrivate: true, type: 'INVALID', reason: 'Empty or missing IP' };
    }

    const ipVersion = net.isIP(clean);
    if (ipVersion === 0) {
      return { isPrivate: true, type: 'INVALID', reason: 'Invalid IP address syntax' };
    }

    // 1. IPv4 Classification (32-bit standard blocks)
    if (ipVersion === 4) {
      const parts = clean.split('.').map((p) => parseInt(p, 10));
      if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
        return { isPrivate: true, type: 'INVALID', reason: 'Octet value exceeds 255 or invalid format' };
      }

      const [p0, p1, p2, p3] = parts;

      // 0.0.0.0/8 (Current network / RFC 1122 / RFC 6890)
      if (p0 === 0) {
        return { isPrivate: true, type: 'UNSPECIFIED', reason: 'RFC 1122 Current Network (0.0.0.0/8)' };
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

    // 2. IPv6 Classification (128-bit standard blocks)
    if (ipVersion === 6) {
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
        if (net.isIPv4(embeddedV4)) {
          return this.isPrivateOrReserved(embeddedV4);
        }
      }

      // Multicast (ff00::/8 / RFC 4291)
      if (clean.startsWith('ff')) {
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

      return { isPrivate: false, type: 'PUBLIC' };
    }

    return { isPrivate: true, type: 'INVALID', reason: 'Unrecognized IP format' };
  }

  /**
   * Resolves geolocation for an IP address.
   * Public IPs are looked up via live GeoIP provider (or local SQLite cache).
   * Non-public IPs are strictly labeled without external network queries.
   */
  async getLocation(ip: string): Promise<GeoLocationData> {
    const cleanIp = GeoLocationProvider.normalizeIp(ip);
    const classification = GeoLocationProvider.isPrivateOrReserved(cleanIp);

    console.log(`[GeoIP] Received header: "${ip}"`);
    console.log(`[GeoIP] Extracted IP: ${cleanIp || 'None'}`);
    console.log(`[GeoIP] Normalized IP: ${cleanIp || 'None'}`);
    console.log(`[GeoIP] Classification: ${classification.type}`);

    // CRITICAL RULE: ONLY an IP classified as PUBLIC may trigger GeoIP.
    // Non-public IPs bypass GeoIP completely.
    if (classification.type !== 'PUBLIC') {
      let statusMsg = 'Location unavailable — private/internal IP';
      let errorMsg = classification.reason || 'Private/internal IP';

      if (classification.type === 'PRIVATE') {
        statusMsg = 'Location unavailable — private/internal IP';
        errorMsg = 'Private/internal IP';
      } else if (classification.type === 'LOOPBACK') {
        statusMsg = 'Location unavailable — loopback IP';
        errorMsg = 'Loopback IP address';
      } else if (classification.type === 'DOCUMENTATION') {
        statusMsg = 'Location unavailable — documentation/test IP';
        errorMsg = 'Documentation IP address';
      } else if (classification.type === 'INVALID') {
        statusMsg = 'Location unavailable — invalid IP format';
        errorMsg = 'Invalid IP address syntax';
      } else {
        statusMsg = `Location unavailable — ${classification.type.toLowerCase()} IP`;
      }

      return {
        ip: cleanIp,
        classification: classification.type,
        geoAvailable: false,
        country: null,
        countryCode: null,
        region: null,
        city: null,
        postalCode: null,
        latitude: null,
        longitude: null,
        lat: null,
        lon: null,
        timezone: null,
        asn: null,
        organization: null,
        org: null,
        isp: null,
        network: null,
        provider: null,
        lookupTimestamp: new Date().toISOString(),
        error: errorMsg,
        isPrivate: true,
        isPublic: false,
        location: null,
        reason: errorMsg,
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
      console.log(`[GeoIP] Lookup failed: GeoIP lookup disabled`);

      return {
        ip: cleanIp,
        classification: 'PUBLIC',
        geoAvailable: false,
        country: null,
        countryCode: null,
        region: null,
        city: null,
        postalCode: null,
        latitude: null,
        longitude: null,
        lat: null,
        lon: null,
        timezone: null,
        asn: null,
        organization: null,
        org: null,
        isp: null,
        network: null,
        provider: 'provider_disabled',
        lookupTimestamp: new Date().toISOString(),
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

    // 2. Check local SQLite cache first (keyed by normalized public IP)
    try {
      const cached = DatabaseService.getCachedGeoLocation(cleanIp);
      if (cached && cached.country) {
        const hasValidCoords =
          typeof cached.latitude === 'number' &&
          typeof cached.longitude === 'number' &&
          cached.latitude >= -90 &&
          cached.latitude <= 90 &&
          cached.longitude >= -180 &&
          cached.longitude <= 180 &&
          !(cached.latitude === 0 && cached.longitude === 0);

        console.log(`[GeoIP] Provider response status: Cache hit (SQLite)`);
        console.log(`[GeoIP] Country: ${cached.country}`);
        console.log(`[GeoIP] City: ${cached.city || 'N/A'}`);
        console.log(`[GeoIP] ASN: ${cached.asn || 'N/A'}`);
        console.log(`[GeoIP] Latitude: ${hasValidCoords ? cached.latitude : 'None'}`);
        console.log(`[GeoIP] Longitude: ${hasValidCoords ? cached.longitude : 'None'}`);
        console.log(`[GeoIP] Lookup completed`);

        return {
          ip: cleanIp,
          classification: 'PUBLIC',
          geoAvailable: hasValidCoords,
          country: cached.country,
          countryCode: cached.countryCode || null,
          region: cached.region || null,
          city: cached.city || null,
          postalCode: (cached as any).postalCode || null,
          latitude: hasValidCoords ? cached.latitude : null,
          longitude: hasValidCoords ? cached.longitude : null,
          lat: hasValidCoords ? cached.latitude : null,
          lon: hasValidCoords ? cached.longitude : null,
          timezone: cached.timezone || null,
          asn: cached.asn || null,
          organization: cached.organization || cached.org || null,
          org: cached.organization || cached.org || null,
          isp: cached.isp || null,
          network: cached.network || null,
          provider: cached.provider || 'sqlite_cache',
          lookupTimestamp: (cached as any).lookupTimestamp || new Date().toISOString(),
          error: null,
          isPrivate: false,
          isPublic: true,
          location: cached.city ? `${cached.city}, ${cached.country}` : cached.country,
          reason: undefined,
          ipType: 'PUBLIC',
          lookupStatus: 'resolved',
          statusMessage: 'Resolved via live GeoIP provider',
          source: 'sqlite_cache',
        };
      }
    } catch {
      // Database cache read error - proceed to live lookup
    }

    // 3. Fetch live data from real GeoIP service
    // Primary: ip-api.com
    // Fallback: ipwho.is
    const lookupTimeoutMs = 4000;

    // Strategy A: Primary ip-api.com
    try {
      const primaryUrl = process.env.GEOIP_API_URL
        ? `${process.env.GEOIP_API_URL.replace(/\/$/, '')}/${encodeURIComponent(cleanIp)}`
        : `http://ip-api.com/json/${encodeURIComponent(cleanIp)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query`;

      console.log(`[GeoIP] Provider request: ${primaryUrl}`);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), lookupTimeoutMs);

      const headers: Record<string, string> = {
        'User-Agent': 'MailTrace-AI-Forensics/1.0',
      };
      if (process.env.GEOIP_API_KEY) {
        headers['Authorization'] = `Bearer ${process.env.GEOIP_API_KEY}`;
      }

      const res = await fetch(primaryUrl, { signal: controller.signal, headers });
      clearTimeout(timer);

      console.log(`[GeoIP] Provider HTTP status: ${res.status}`);

      if (res.ok) {
        const data = (await res.json()) as any;
        console.log(`[GeoIP] Provider response received`);

        if (data && data.status === 'success') {
          const lat = typeof data.lat === 'number' && !isNaN(data.lat) && data.lat >= -90 && data.lat <= 90 ? data.lat : null;
          const lon = typeof data.lon === 'number' && !isNaN(data.lon) && data.lon >= -180 && data.lon <= 180 ? data.lon : null;
          const validCoords = lat !== null && lon !== null && !(lat === 0 && lon === 0);
          const parsedAsn = data.as ? data.as.split(' ')[0] : null;

          console.log(`[GeoIP] Country: ${data.country || 'N/A'}`);
          console.log(`[GeoIP] City: ${data.city || 'N/A'}`);
          console.log(`[GeoIP] ASN: ${parsedAsn || 'N/A'}`);
          console.log(`[GeoIP] Latitude: ${validCoords ? lat : 'None'}`);
          console.log(`[GeoIP] Longitude: ${validCoords ? lon : 'None'}`);
          console.log(`[GeoIP] Lookup completed`);

          const result: GeoLocationData = {
            ip: cleanIp,
            classification: 'PUBLIC',
            geoAvailable: validCoords,
            country: data.country || null,
            countryCode: data.countryCode || null,
            region: data.regionName || null,
            city: data.city || null,
            postalCode: data.zip || null,
            latitude: validCoords ? lat : null,
            longitude: validCoords ? lon : null,
            lat: validCoords ? lat : null,
            lon: validCoords ? lon : null,
            timezone: data.timezone || null,
            asn: parsedAsn,
            organization: data.org || null,
            org: data.org || null,
            isp: data.isp || null,
            network: null,
            provider: 'ip-api.com',
            lookupTimestamp: new Date().toISOString(),
            error: null,
            isPrivate: false,
            isPublic: true,
            location: data.country ? (data.city ? `${data.city}, ${data.country}` : data.country) : null,
            reason: undefined,
            ipType: 'PUBLIC',
            lookupStatus: 'resolved',
            statusMessage: 'Resolved via live GeoIP provider',
            source: 'ip-api.com',
          };

          // Cache in SQLite
          try {
            DatabaseService.cacheGeoLocation(cleanIp, result);
          } catch {}

          return result;
        } else if (data && data.status === 'fail') {
          console.log(`[GeoIP] Provider error: ${data.message || 'Lookup failed'}`);
        }
      }
    } catch (err: any) {
      console.log(`[GeoIP] Provider error: ${err.message || err}`);
    }

    // Strategy B: Fallback to ipwho.is if primary is rate limited or unavailable
    try {
      const fallbackUrl = `https://ipwho.is/${encodeURIComponent(cleanIp)}`;
      console.log(`[GeoIP] Provider request (fallback): ${fallbackUrl}`);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), lookupTimeoutMs);

      const res = await fetch(fallbackUrl, {
        signal: controller.signal,
        headers: { 'User-Agent': 'MailTrace-AI-Forensics/1.0' },
      });
      clearTimeout(timer);

      console.log(`[GeoIP] Provider HTTP status (fallback): ${res.status}`);

      if (res.ok) {
        const data = (await res.json()) as any;
        console.log(`[GeoIP] Provider response received (fallback)`);

        if (data && data.success) {
          const lat = typeof data.latitude === 'number' && !isNaN(data.latitude) && data.latitude >= -90 && data.latitude <= 90 ? data.latitude : null;
          const lon = typeof data.longitude === 'number' && !isNaN(data.longitude) && data.longitude >= -180 && data.longitude <= 180 ? data.longitude : null;
          const validCoords = lat !== null && lon !== null && !(lat === 0 && lon === 0);
          const asnStr = data.connection?.asn ? `AS${data.connection.asn}` : null;

          console.log(`[GeoIP] Country: ${data.country || 'N/A'}`);
          console.log(`[GeoIP] City: ${data.city || 'N/A'}`);
          console.log(`[GeoIP] ASN: ${asnStr || 'N/A'}`);
          console.log(`[GeoIP] Latitude: ${validCoords ? lat : 'None'}`);
          console.log(`[GeoIP] Longitude: ${validCoords ? lon : 'None'}`);
          console.log(`[GeoIP] Lookup completed`);

          const result: GeoLocationData = {
            ip: cleanIp,
            classification: 'PUBLIC',
            geoAvailable: validCoords,
            country: data.country || null,
            countryCode: data.country_code || null,
            region: data.region || null,
            city: data.city || null,
            postalCode: data.postal || null,
            latitude: validCoords ? lat : null,
            longitude: validCoords ? lon : null,
            lat: validCoords ? lat : null,
            lon: validCoords ? lon : null,
            timezone: data.timezone?.id || null,
            asn: asnStr,
            organization: data.connection?.org || null,
            org: data.connection?.org || null,
            isp: data.connection?.isp || null,
            network: null,
            provider: 'ipwho.is',
            lookupTimestamp: new Date().toISOString(),
            error: null,
            isPrivate: false,
            isPublic: true,
            location: data.country ? (data.city ? `${data.city}, ${data.country}` : data.country) : null,
            reason: undefined,
            ipType: 'PUBLIC',
            lookupStatus: 'resolved',
            statusMessage: 'Resolved via live GeoIP provider',
            source: 'ipwho.is',
          };

          // Cache in SQLite
          try {
            DatabaseService.cacheGeoLocation(cleanIp, result);
          } catch {}

          return result;
        }
      }
    } catch (err: any) {
      console.log(`[GeoIP] Provider error (fallback): ${err.message || err}`);
    }

    // 4. Fallback when GeoIP lookup is unavailable (Section 13)
    console.log(`[GeoIP] Lookup failed: GeoIP lookup unavailable`);
    console.log(`[GeoIP] Parse error: All live GeoIP providers failed or timed out`);

    return {
      ip: cleanIp,
      classification: 'PUBLIC',
      geoAvailable: false,
      country: null,
      countryCode: null,
      region: null,
      city: null,
      postalCode: null,
      latitude: null,
      longitude: null,
      lat: null,
      lon: null,
      timezone: null,
      asn: null,
      organization: null,
      org: null,
      isp: null,
      network: null,
      provider: 'unavailable',
      lookupTimestamp: new Date().toISOString(),
      error: 'GeoIP lookup unavailable',
      isPrivate: false,
      isPublic: true,
      location: null,
      reason: 'GeoIP lookup unavailable',
      ipType: 'PUBLIC',
      lookupStatus: 'lookup_failed',
      statusMessage: 'Location unavailable — GeoIP lookup unavailable',
      source: 'unavailable',
    };
  }
}

export const geoProvider = new GeoLocationProvider();
