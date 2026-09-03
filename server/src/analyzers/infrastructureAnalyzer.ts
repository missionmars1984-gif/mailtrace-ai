import type { RouteHop, SecurityFinding, GeoLocationData } from '../types/index.js';
import { geoProvider, GeoLocationProvider } from '../services/geoLocationProvider.js';

export class InfrastructureAnalyzer {
  static isPrivateIp(ip: string): boolean {
    return GeoLocationProvider.isPrivateOrReserved(ip).isPrivate;
  }

  static async lookupIp(ip: string): Promise<GeoLocationData> {
    return geoProvider.getLocation(ip);
  }

  static async enrichHops(rawHops: RouteHop[]): Promise<{ hops: RouteHop[]; findings: SecurityFinding[] }> {
    const findings: SecurityFinding[] = [];
    const enrichedHops: RouteHop[] = [];

    for (let i = 0; i < rawHops.length; i++) {
      const hop = rawHops[i];
      const ip = hop.ip ? hop.ip.trim() : '';
      let geo: GeoLocationData | undefined;
      let isPrivate = false;

      if (ip) {
        geo = await geoProvider.getLocation(ip);
        isPrivate = Boolean(geo.isPrivate);
      }

      const enriched: RouteHop = {
        ...hop,
        isPrivate,
        geo,
      };

      enrichedHops.push(enriched);

      // Inspect originating hop (innermost/last hop in reverse transport order)
      if (i === rawHops.length - 1 && ip) {
        if (isPrivate) {
          findings.push({
            type: 'INFRASTRUCTURE',
            severity: 'INFO',
            title: 'Internal / Private Originating Relay',
            source: 'Infrastructure',
            observed: `Origin hop: ${ip} (${geo?.city || 'RFC 1918 Private'})`,
            impact: 'Geolocation unavailable — private/internal IP. Mail server relayed through an intranet gateway or private upstream cluster.',
          });
        } else if (geo) {
          const orgLower = (geo.org || '').toLowerCase();
          const ispLower = (geo.isp || '').toLowerCase();

          if (orgLower.includes('tor') || ispLower.includes('tor') || orgLower.includes('relay') || orgLower.includes('proxy')) {
            findings.push({
              type: 'INFRASTRUCTURE',
              severity: 'CRITICAL',
              title: 'Anonymizing Tor / Proxy Relay Origin',
              source: 'Infrastructure',
              observed: `Origin infrastructure: ${ip} (${geo.org || geo.isp || 'Tor Exit Node'})`,
              impact: 'Sender routed transmission through an anonymized proxy network to obfuscate origin infrastructure.',
            });
          } else {
            findings.push({
              type: 'INFRASTRUCTURE',
              severity: 'INFO',
              title: 'Observed Public Infrastructure Relay',
              source: 'Infrastructure',
              observed: `Origin gateway: ${ip} [${geo.city ? geo.city + ', ' : ''}${geo.country}] (${geo.asn || 'Public ASN'} ${geo.org || ''})`,
              impact: 'Observed email infrastructure geolocates to this autonomous network. Approximate network location; does not prove human sender identity.',
            });
          }
        }
      }
    }

    return { hops: enrichedHops, findings };
  }
}
