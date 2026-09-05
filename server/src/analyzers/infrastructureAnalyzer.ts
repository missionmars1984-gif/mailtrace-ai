import type { RouteHop, SecurityFinding, GeoLocationData, GeoPipelineDiagnostic } from '../types/index.js';
import { geoProvider, GeoLocationProvider } from '../services/geoLocationProvider.js';

export class InfrastructureAnalyzer {
  static isPrivateIp(ip: string): boolean {
    return GeoLocationProvider.isPrivateOrReserved(ip).isPrivate;
  }

  static async lookupIp(ip: string): Promise<GeoLocationData> {
    return geoProvider.getLocation(ip);
  }

  static async enrichHops(rawHops: RouteHop[]): Promise<{
    hops: RouteHop[];
    findings: SecurityFinding[];
    diagnostic: GeoPipelineDiagnostic;
    observedOriginRelay?: RouteHop;
  }> {
    const findings: SecurityFinding[] = [];
    const enrichedHops: RouteHop[] = [];

    // 1. Enrich every hop with classification, GeoIP, and ASN data
    for (let i = 0; i < rawHops.length; i++) {
      const hop = rawHops[i];
      const ip = hop.ip ? hop.ip.trim() : '';
      let geo: GeoLocationData | undefined;
      let isPrivate = false;

      if (ip) {
        geo = await geoProvider.getLocation(ip);
        isPrivate = Boolean(geo.isPrivate);
      }

      const classification = geo?.ipType || hop.ipType || (isPrivate ? 'PRIVATE' : (ip ? 'PUBLIC' : 'INVALID'));

      const isPublic = !isPrivate && Boolean(ip);
      const geoAvailable = Boolean(geo?.geoAvailable ?? (geo?.lat !== undefined && geo?.lon !== undefined && geo?.lookupStatus === 'resolved'));

      const enriched: RouteHop = {
        ...hop,
        hostname: hop.hostname || (hop.from ? hop.from.split(/\s+/)[0].trim() : undefined),
        isPrivate,
        isPublic,
        geoAvailable,
        location: geo?.location ?? null,
        reason: geo?.reason,
        ipType: classification,
        classification,
        country: geo?.country,
        countryCode: geo?.countryCode,
        region: geo?.region,
        city: geo?.city,
        lat: geo?.lat,
        lon: geo?.lon,
        latitude: geo?.latitude ?? geo?.lat,
        longitude: geo?.longitude ?? geo?.lon,
        asn: geo?.asn,
        org: geo?.org,
        organization: geo?.organization ?? geo?.org,
        isp: geo?.isp,
        provider: geo?.provider,
        error: geo?.error,
        statusMessage: geo?.statusMessage,
        lookupStatus: geo?.lookupStatus || (isPrivate ? 'private_ip' : 'unavailable'),
        geo,
      };

      // Diagnostic logging of complete chain for this hop
      console.log(`[GEO PIPELINE] Hop #${enriched.hopNumber}:
  Received header: "${enriched.rawHopText?.substring(0, 100) || 'N/A'}..."
  IP extracted:    ${ip || 'None'}
  Normalized IP:   ${geo?.ip || ip || 'None'}
  Classification:  ${classification} (isPrivate: ${isPrivate})
  Action:          ${!isPrivate && ip ? 'PUBLIC IP -> Querying GeoIP Provider' : (isPrivate ? 'PRIVATE IP -> Returning "Geolocation unavailable — private/internal IP"' : 'NO IP')}
  GeoIP Status:    ${enriched.lookupStatus}
  Country:         ${enriched.country || 'N/A'}
  City:            ${enriched.city || 'N/A'}
  ASN:             ${enriched.asn || 'N/A'}
  Organization:    ${enriched.org || 'N/A'}`);

      enrichedHops.push(enriched);
    }

    // 2. Identify the Earliest Trustworthy Public Relay (Chronological Walk: Hop 1 -> Hop N)
    // The first public IP encountered after internal client hops is the origin gateway into the public internet
    const publicOriginHop = enrichedHops.find((h) => h.ip && !h.isPrivate);

    if (publicOriginHop) {
      publicOriginHop.isPublicOriginRelay = true;

      const geo = publicOriginHop.geo;
      const orgLower = (geo?.org || '').toLowerCase();
      const ispLower = (geo?.isp || '').toLowerCase();
      const isTorOrProxy = orgLower.includes('tor') || ispLower.includes('tor') || orgLower.includes('relay') || orgLower.includes('proxy');

      if (isTorOrProxy) {
        findings.push({
          type: 'INFRASTRUCTURE',
          severity: 'CRITICAL',
          title: 'Anonymizing Tor / Proxy Relay Origin',
          source: 'Infrastructure',
          observed: `Observed mail infrastructure location: ${publicOriginHop.ip} (${geo?.org || geo?.isp || 'Tor Exit Node'})`,
          impact: 'Sender routed transmission through an anonymized proxy network to obfuscate origin infrastructure. GeoIP shows the observable infrastructure associated with the email route. It does not establish the attacker\'s physical identity or exact location.',
        });
      } else {
        findings.push({
          type: 'INFRASTRUCTURE',
          severity: 'INFO',
          title: 'Observed Mail Infrastructure Location',
          source: 'Infrastructure',
          observed: `Location of the observed public IP: ${publicOriginHop.ip} [${geo?.city ? geo.city + ', ' : ''}${geo?.country || 'Unknown'}] (${geo?.asn || 'Public ASN'} ${geo?.org || ''})`,
          impact: 'GeoIP shows the observable infrastructure associated with the email route. It does not establish the attacker\'s physical identity or exact location.',
        });
      }
    } else if (enrichedHops.some((h) => h.ip && h.isPrivate)) {
      // All observed IPs are private/internal
      findings.push({
        type: 'INFRASTRUCTURE',
        severity: 'INFO',
        title: 'Internal / Private Infrastructure Only',
        source: 'Infrastructure',
        observed: `All observed hops belong to private/internal RFC 1918 or loopback address blocks.`,
        impact: 'Geolocation unavailable — private/internal IP. Location unavailable — private/internal IP.',
      });
    } else {
      findings.push({
        type: 'INFRASTRUCTURE',
        severity: 'INFO',
        title: 'No Routable IPs Found',
        source: 'Infrastructure',
        observed: 'No routable IP addresses detected in transport headers.',
        impact: 'No routable IPs found. Location unavailable — no transport IPs.',
      });
    }

    // Mark Hop 1 as transmission origin (chronological beginning)
    if (enrichedHops.length > 0) {
      enrichedHops[0].isOrigin = true;
    }

    // 3. Compute Pipeline Diagnostic Telemetry
    const totalHeaders = rawHops.filter((h) => !h.from?.includes('Client MUA') && !h.from?.includes('SPF Designated')).length;
    const ipsExtracted = rawHops.filter((h) => Boolean(h.ip)).length;
    const publicIps = enrichedHops.filter((h) => h.ip && !h.isPrivate).length;
    const privateIps = enrichedHops.filter((h) => h.ip && h.isPrivate).length;
    const ipsSentToGeoIp = enrichedHops.filter((h) => h.ip && !h.isPrivate && h.geo?.source !== 'sqlite_cache' && h.geo?.source !== 'rfc_boundary_filter').length;
    const geoIpResponses = enrichedHops.filter((h) => h.geo?.lookupStatus === 'resolved').length;
    const failedLookups = enrichedHops.filter((h) => h.ip && !h.isPrivate && h.geo?.lookupStatus !== 'resolved').length;

    const diagnostic: GeoPipelineDiagnostic = {
      receivedHeadersFound: totalHeaders,
      ipsExtracted,
      publicIps,
      privateIps,
      ipsSentToGeoIp,
      geoIpResponses,
      failedLookups,
      routeHops: enrichedHops.length,
      observedPublicOriginRelay: publicOriginHop
        ? `${publicOriginHop.ip} (${publicOriginHop.geo?.city ? publicOriginHop.geo.city + ', ' : ''}${publicOriginHop.geo?.country || 'Unknown'} - ${publicOriginHop.geo?.asn || ''} ${publicOriginHop.geo?.org || ''})`
        : undefined,
    };

    // Diagnostic console output for analyzed message
    console.log(`
==================== [MAILTRACE GEO PIPELINE DIAGNOSTIC] ====================
Received headers found:        ${diagnostic.receivedHeadersFound}
IPs extracted:                 ${diagnostic.ipsExtracted}
Public IPs:                    ${diagnostic.publicIps}
Private IPs:                   ${diagnostic.privateIps}
IPs sent to GeoIP:             ${diagnostic.ipsSentToGeoIp}
GeoIP responses:               ${diagnostic.geoIpResponses}
Failed lookups:                ${diagnostic.failedLookups}
Route hops:                    ${diagnostic.routeHops}
Observed public origin relay:  ${diagnostic.observedPublicOriginRelay || 'None (Private or Unrouted)'}
=============================================================================
    `);

    return {
      hops: enrichedHops,
      findings,
      diagnostic,
      observedOriginRelay: publicOriginHop,
    };
  }
}
