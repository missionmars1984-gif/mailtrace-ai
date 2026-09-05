import crypto from 'node:crypto';
import type { Request } from 'express';
import type { TrackingEvent, LocationHypothesis } from '../types/index.js';
import { DatabaseService } from '../db/database.js';
import { geoProvider, GeoLocationProvider } from './geoLocationProvider.js';
import { NetworkClassifier } from './networkClassifier.js';

export class TrackingService {
  /**
   * 1x1 Transparent GIF buffer (43 bytes standard GIF89a)
   */
  static readonly TRANSPARENT_GIF = Buffer.from(
    'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
    'base64'
  );

  /**
   * Extracts clean, normalized client IP from Express request.
   */
  static getClientIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = '';
    if (typeof forwarded === 'string') {
      // First IP in list is original client
      ip = forwarded.split(',')[0].trim();
    } else if (Array.isArray(forwarded) && forwarded.length > 0) {
      ip = forwarded[0].trim();
    } else if (req.socket.remoteAddress) {
      ip = req.socket.remoteAddress;
    }
    return GeoLocationProvider.normalizeIp(ip);
  }

  /**
   * Records an email interaction (open or click) and triggers attribution synthesis.
   */
  static async recordEvent(params: {
    caseId: string;
    eventType: 'open' | 'click';
    req: Request;
    targetUrl?: string;
  }): Promise<TrackingEvent> {
    const ip = this.getClientIp(params.req);
    const userAgent = (params.req.headers['user-agent'] as string) || '';
    const eventId = `trk_${crypto.randomUUID()}`;
    const timestamp = new Date().toISOString();

    // Enrich IP
    let geoHypothesis: LocationHypothesis | undefined;
    let isPrefetchOrProxy = false;
    let proxyType: 'APPLE_MPP' | 'GOOGLE_PROXY' | 'SECURITY_SCANNER' | 'GENUINE_CLIENT' | 'UNKNOWN' = 'UNKNOWN';

    if (ip && GeoLocationProvider.isValidIp(ip)) {
      const geo = await geoProvider.getLocation(ip);
      const network = NetworkClassifier.classify({
        ip,
        asn: geo.asn,
        org: geo.org,
        isp: geo.isp,
        userAgent,
      });

      if (network.detectedIntermediary === 'Apple MPP Proxy') {
        isPrefetchOrProxy = true;
        proxyType = 'APPLE_MPP';
      } else if (network.detectedIntermediary === 'Google Image Proxy') {
        isPrefetchOrProxy = true;
        proxyType = 'GOOGLE_PROXY';
      } else if (network.detectedIntermediary === 'Security Scanner') {
        isPrefetchOrProxy = true;
        proxyType = 'SECURITY_SCANNER';
      } else if (!network.isPrivacyRelayOrProxy && !network.isCloudOrHosting) {
        proxyType = 'GENUINE_CLIENT';
      }

      const evidence: string[] = [];
      const limitations: string[] = [];

      evidence.push(`Interaction recorded: ${params.eventType.toUpperCase()} event from IP ${ip}`);
      if (geo.city || geo.country) {
        evidence.push(`Observed client network location: ${geo.city ? geo.city + ', ' : ''}${geo.country || 'Unknown'}`);
      }
      evidence.push(`Network: ${network.providerCategory} (${geo.asn || 'Unassigned ASN'})`);

      if (isPrefetchOrProxy) {
        limitations.push(`Intermediary detected: ${network.detectedIntermediary}. This interaction was triggered by a privacy/security proxy, not the recipient device.`);
      }

      geoHypothesis = {
        ip,
        country: geo.country || null,
        countryCode: geo.countryCode || null,
        region: geo.region || null,
        city: geo.city || null,
        latitude: geo.latitude ?? geo.lat ?? null,
        longitude: geo.longitude ?? geo.lon ?? null,
        accuracyRadiusKm: network.accuracyEstimateKm,
        confidence: isPrefetchOrProxy ? 10 : (network.isResidentialOrMobile ? 85 : 50),
        confidenceLevel: isPrefetchOrProxy ? 'VERY_LOW' : (network.isResidentialOrMobile ? 'HIGH' : 'MODERATE'),
        networkType: network.networkType,
        asn: geo.asn || null,
        isp: geo.isp || null,
        organization: geo.org || geo.organization || null,
        evidence,
        limitations,
        sourceSignals: [`Interaction Event (${params.eventType.toUpperCase()})`],
        hypothesisType: 'INTERACTION',
      };
    }

    const trackingEvent: TrackingEvent = {
      id: eventId,
      caseId: params.caseId,
      eventType: params.eventType,
      ip: ip || '127.0.0.1',
      userAgent,
      timestamp,
      isPrefetchOrProxy,
      proxyType,
      targetUrl: params.targetUrl,
      geo: geoHypothesis,
    };

    // Save to database
    DatabaseService.saveTrackingEvent(trackingEvent);

    return trackingEvent;
  }
}
