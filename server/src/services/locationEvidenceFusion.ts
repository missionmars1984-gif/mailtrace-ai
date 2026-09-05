import type {
  CaseRecord,
  RouteHop,
  TrackingEvent,
  LocationHypothesis,
  MultiSignalGeoAttribution,
  ConfidenceLevel,
  NetworkClassificationType,
} from '../types/index.js';
import { NetworkClassifier } from './networkClassifier.js';
import { LocationProfiler } from './locationProfiler.js';

export const GEO_ATTRIBUTION_WEIGHTS = {
  // Base confidence by signal origin
  originHopPublicRelayBase: 80,
  intermediateHopBase: 50,
  genuineClientInteractionBase: 85,
  proxyInteractionBase: 10,

  // Network type modifiers on Estimated User Location
  residentialModifier: 15,
  mobileModifier: 10,
  corporateModifier: 0,
  educationalModifier: 10,
  cloudHostingPenalty: 65,
  vpnTorPenalty: 60,
  privacyRelayPenalty: 75,

  // Corroboration bonuses
  interactionOriginAlignmentBonus: 20,
  timezoneAlignmentBonus: 10,
  historicalProfileAlignmentBonus: 15,

  // Conflict penalties
  impossibleTravelPenalty: 30,
  timezoneMismatchPenalty: 25,
  historicalDeviationPenalty: 20,
};

function getConfidenceLevel(score: number): ConfidenceLevel {
  if (score >= 80) return 'VERY_HIGH';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MODERATE';
  if (score >= 20) return 'LOW';
  return 'VERY_LOW';
}

export class LocationEvidenceFusion {
  /**
   * Synthesizes multi-signal email geolocation and attribution across transport headers,
   * network classification, interaction tracking telemetry, and historical baselines.
   */
  static synthesize(params: {
    originRelay?: RouteHop;
    clientSubmissionHop?: RouteHop;
    hops: RouteHop[];
    trackingEvents?: TrackingEvent[];
    senderAddress?: string;
    dateHeader?: string;
  }): MultiSignalGeoAttribution {
    const { originRelay, hops, trackingEvents = [], senderAddress = '', dateHeader } = params;
    const clientSubmissionHop = params.clientSubmissionHop || hops.find((h) => h.isClientSubmission);

    const anomalies: string[] = [];
    const limitations: string[] = [
      'Email geolocation reflects registered autonomous system routing and network infrastructure, not physical device GPS or street address.',
    ];
    const competingHypotheses: LocationHypothesis[] = [];

    // =========================================================================
    // 1. Sending Infrastructure Location Hypothesis
    // =========================================================================
    let sendingInfrastructure: LocationHypothesis | null = null;
    const targetHop = originRelay || hops.find((h) => h.ip && !h.isPrivate) || hops[0];

    let infraNetwork = NetworkClassifier.classify({
      ip: targetHop?.ip,
      asn: targetHop?.asn || targetHop?.geo?.asn,
      org: targetHop?.org || targetHop?.geo?.org || targetHop?.geo?.organization,
      isp: targetHop?.isp || targetHop?.geo?.isp,
      hostname: targetHop?.hostname,
    });

    if (targetHop && targetHop.ip && !targetHop.isPrivate && (targetHop.geoAvailable || targetHop.country || targetHop.geo?.country)) {
      const geo = targetHop.geo;
      const country = geo?.country || targetHop.country || null;
      const city = geo?.city || targetHop.city || null;
      const lat = targetHop.latitude ?? targetHop.lat ?? geo?.latitude ?? geo?.lat ?? null;
      const lon = targetHop.longitude ?? targetHop.lon ?? geo?.longitude ?? geo?.lon ?? null;

      const infraEvidence: string[] = [
        `Observed transmitting relay IP: ${targetHop.ip} (Hop #${targetHop.hopNumber || 1})`,
        `Autonomous System: ${targetHop.asn || geo?.asn || 'Unassigned'} — ${geo?.org || geo?.isp || targetHop.organization || 'Public Network'}`,
        `Identified infrastructure type: ${infraNetwork.providerCategory}`,
      ];

      const infraLimitations: string[] = [
        'Represents the mail transport gateway / intermediate relay, which may be decoupled from the sending author.',
      ];

      if (infraNetwork.isCloudOrHosting) {
        infraLimitations.push('Datacenter cloud hosting identified. This IP represents a virtual server facility, not an end-user workstation.');
      }

      sendingInfrastructure = {
        ip: targetHop.ip,
        country,
        countryCode: geo?.countryCode || targetHop.countryCode || null,
        region: geo?.region || targetHop.region || null,
        city,
        latitude: lat,
        longitude: lon,
        accuracyRadiusKm: infraNetwork.accuracyEstimateKm,
        confidence: 85,
        confidenceLevel: 'VERY_HIGH',
        networkType: infraNetwork.networkType,
        asn: targetHop.asn || geo?.asn || null,
        isp: targetHop.isp || geo?.isp || null,
        organization: geo?.org || geo?.organization || null,
        evidence: infraEvidence,
        limitations: infraLimitations,
        sourceSignals: ['RFC 5322 Received Headers', 'Autonomous System Routing'],
        hypothesisType: 'INFRASTRUCTURE',
      };
    } else if (targetHop && targetHop.isPrivate) {
      limitations.push('Observed sending hops belong exclusively to RFC 1918 private address space. External infrastructure location is unobservable.');
      sendingInfrastructure = {
        ip: targetHop.ip,
        country: null,
        countryCode: null,
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        accuracyRadiusKm: 0,
        confidence: 0,
        confidenceLevel: 'VERY_LOW',
        networkType: 'UNKNOWN',
        asn: null,
        isp: null,
        organization: 'Private Internal Network',
        evidence: ['Internal RFC 1918 hop identified without public transit metadata.'],
        limitations: ['Internal private IP — not geolocatable on public internet.'],
        sourceSignals: ['Private Transport Hop'],
        hypothesisType: 'INFRASTRUCTURE',
      };
    }

    // =========================================================================
    // 2. Email Interaction Location Hypothesis (Opens & Clicks)
    // =========================================================================
    let interactionLocation: LocationHypothesis | null = null;
    const genuineEvents = trackingEvents.filter((e) => !e.isPrefetchOrProxy);
    const proxyEvents = trackingEvents.filter((e) => e.isPrefetchOrProxy);

    if (genuineEvents.length > 0) {
      const latestGenuine = genuineEvents[genuineEvents.length - 1];
      if (latestGenuine.geo) {
        interactionLocation = {
          ...latestGenuine.geo,
          confidence: 80,
          confidenceLevel: 'HIGH',
          evidence: [
            ...((latestGenuine.geo as any).evidence || []),
            `Verified human recipient interaction (${(latestGenuine.eventType || latestGenuine.type || '').toUpperCase()}) recorded at ${latestGenuine.timestamp}`,
          ],
        };
      }
    } else if (proxyEvents.length > 0) {
      const latestProxy = proxyEvents[proxyEvents.length - 1];
      if (latestProxy.geo) {
        interactionLocation = {
          ...latestProxy.geo,
          confidence: 10,
          confidenceLevel: 'VERY_LOW',
          evidence: [
            ...((latestProxy.geo as any).evidence || []),
            `Interaction captured via intermediary proxy (${latestProxy.proxyType}) at ${latestProxy.timestamp}`,
          ],
          limitations: [
            'Interaction generated by privacy caching proxy (e.g. Apple Mail Privacy Protection or Google Image Proxy). Location reflects caching edge, not recipient.',
          ],
        };
      }
    }

    // =========================================================================
    // 3. Historical Profiling & Timezone Checks
    // =========================================================================
    const historical = LocationProfiler.analyzeHistoricalProfile(
      senderAddress,
      sendingInfrastructure?.country,
      sendingInfrastructure?.asn
    );

    if (historical.isDeviatingFromProfile && historical.anomalyDescription) {
      anomalies.push(historical.anomalyDescription);
      limitations.push('Sender identity behavior deviates sharply from established historical telemetry.');
    }

    const timezoneCheck = LocationProfiler.checkTimezoneDiscrepancy(
      dateHeader,
      undefined,
      sendingInfrastructure?.longitude
    );

    if (timezoneCheck.hasTimezoneMismatch && timezoneCheck.anomalyDescription) {
      anomalies.push(timezoneCheck.anomalyDescription);
      limitations.push('Timestamp timezone conflicts with geographical longitude of transmitting relay.');
    }

    // =========================================================================
    // 4. Impossible Travel Detection
    // =========================================================================
    let impossibleTravelDetected = false;

    // Check between Sending Infrastructure and Genuine Interaction
    if (
      sendingInfrastructure &&
      interactionLocation &&
      typeof sendingInfrastructure.latitude === 'number' &&
      typeof interactionLocation.latitude === 'number'
    ) {
      const check = LocationProfiler.checkImpossibleTravel(
        {
          latitude: sendingInfrastructure.latitude,
          longitude: sendingInfrastructure.longitude,
          timestamp: dateHeader ? new Date(dateHeader).toISOString() : new Date().toISOString(),
          label: 'Sending Relay',
        },
        {
          latitude: interactionLocation.latitude,
          longitude: interactionLocation.longitude,
          timestamp: trackingEvents[0]?.timestamp || new Date().toISOString(),
          label: 'Interaction Point',
        }
      );

      if (check.isImpossibleTravel && check.reason) {
        impossibleTravelDetected = true;
        anomalies.push(check.reason);
      }
    }

    // Check between multiple tracking events
    if (trackingEvents.length >= 2) {
      for (let i = 0; i < trackingEvents.length - 1; i++) {
        const e1 = trackingEvents[i];
        const e2 = trackingEvents[i + 1];
        if (e1.geo?.latitude && e2.geo?.latitude && !e1.isPrefetchOrProxy && !e2.isPrefetchOrProxy) {
          const check = LocationProfiler.checkImpossibleTravel(
            {
              latitude: e1.geo.latitude,
              longitude: e1.geo.longitude,
              timestamp: e1.timestamp,
              label: `Interaction #${i + 1}`,
            },
            {
              latitude: e2.geo.latitude,
              longitude: e2.geo.longitude,
              timestamp: e2.timestamp,
              label: `Interaction #${i + 2}`,
            }
          );
          if (check.isImpossibleTravel && check.reason) {
            impossibleTravelDetected = true;
            anomalies.push(check.reason);
            break;
          }
        }
      }
    }

    // =========================================================================
    // 5. Estimated User Location Synthesis
    // =========================================================================
    let estimatedUserLocation: LocationHypothesis | null = null;

    const hasClientSubmission = Boolean(
      clientSubmissionHop &&
      clientSubmissionHop.ip &&
      !clientSubmissionHop.isPrivate &&
      (clientSubmissionHop.geoAvailable || clientSubmissionHop.country || clientSubmissionHop.geo?.country)
    );

    if (hasClientSubmission && clientSubmissionHop) {
      const cGeo = clientSubmissionHop.geo;
      const cCountry = cGeo?.country || clientSubmissionHop.country || null;
      const cCity = cGeo?.city || clientSubmissionHop.city || null;
      const cLat = clientSubmissionHop.latitude ?? clientSubmissionHop.lat ?? cGeo?.latitude ?? cGeo?.lat ?? null;
      const cLon = clientSubmissionHop.longitude ?? clientSubmissionHop.lon ?? cGeo?.longitude ?? cGeo?.lon ?? null;

      const clientNetwork = NetworkClassifier.classify({
        ip: clientSubmissionHop.ip,
        asn: clientSubmissionHop.asn || cGeo?.asn,
        org: clientSubmissionHop.org || cGeo?.org,
        isp: clientSubmissionHop.isp || cGeo?.isp,
        hostname: clientSubmissionHop.hostname,
      });

      if (clientNetwork.isVpnOrTor) {
        estimatedUserLocation = {
          country: `${cCountry || 'Unknown'} (VPN/Proxy Egress)`,
          countryCode: cGeo?.countryCode || clientSubmissionHop.countryCode || null,
          region: cGeo?.region || clientSubmissionHop.region || null,
          city: cCity,
          latitude: cLat,
          longitude: cLon,
          accuracyRadiusKm: 2500,
          confidence: 20,
          confidenceLevel: 'LOW',
          networkType: clientNetwork.networkType,
          asn: clientSubmissionHop.asn || cGeo?.asn || null,
          isp: clientSubmissionHop.isp || cGeo?.isp || null,
          organization: cGeo?.org || clientSubmissionHop.organization || null,
          evidence: [
            `Client MUA submission IP ${clientSubmissionHop.ip} is a known ${clientNetwork.providerCategory} gateway (X-Originating-IP).`,
          ],
          limitations: [
            'Sender connected to webmail/submission MTA through an anonymizing VPN or Proxy.',
            'Coordinates reflect proxy node, not physical user workstation.',
          ],
          sourceSignals: ['Client Submission Header (X-Originating-IP)', 'VPN/Tor Egress Gateway'],
          hypothesisType: 'USER_ESTIMATE',
        };
      } else if (clientNetwork.isCloudOrHosting) {
        estimatedUserLocation = {
          country: 'Inconclusive (Cloud Submission Client)',
          countryCode: null,
          region: null,
          city: null,
          latitude: null,
          longitude: null,
          accuracyRadiusKm: 5000,
          confidence: 25,
          confidenceLevel: 'VERY_LOW',
          networkType: clientNetwork.networkType,
          asn: clientSubmissionHop.asn || cGeo?.asn || null,
          isp: clientSubmissionHop.isp || cGeo?.isp || null,
          organization: cGeo?.org || clientSubmissionHop.organization || null,
          evidence: [
            `Client submission header (X-Originating-IP) recorded datacenter/cloud IP: ${clientSubmissionHop.ip} (${clientNetwork.providerCategory}).`,
          ],
          limitations: [
            'Client submitted message via automated cloud runner or remote virtual machine.',
            'Physical user coordinates are decoupled from cloud hosting facility.',
          ],
          sourceSignals: ['Client Submission Header (X-Originating-IP)', 'Cloud Hosting Infrastructure'],
          hypothesisType: 'USER_ESTIMATE',
        };
      } else if (clientNetwork.isResidentialOrMobile) {
        let userConfidence = clientNetwork.networkType === 'RESIDENTIAL' ? 85 : 80;
        const userEvidence: string[] = [
          `Client MUA submission header (X-Originating-IP) recorded client device IP ${clientSubmissionHop.ip} [${cCity ? cCity + ', ' : ''}${cCountry}].`,
          `Network classified as consumer broadband / mobile carrier (${clientNetwork.providerCategory} — ${clientSubmissionHop.isp || clientSubmissionHop.org || 'Consumer ISP'}).`,
        ];
        const userLimitations: string[] = [
          `Consumer IP geolocation is accurate to metropolitan area (~${clientNetwork.accuracyEstimateKm} km radius), not exact physical dwelling.`,
          'Client submission header inserted by upstream webmail or submission MTA.',
        ];

        const clientTzCheck = LocationProfiler.checkTimezoneDiscrepancy(dateHeader, undefined, cLon);
        if (clientTzCheck.hasTimezoneMismatch) {
          userConfidence -= GEO_ATTRIBUTION_WEIGHTS.timezoneMismatchPenalty;
          userLimitations.push('Date header timezone conflicts with geographic longitude of client submission.');
        } else {
          userConfidence = Math.min(95, userConfidence + GEO_ATTRIBUTION_WEIGHTS.timezoneAlignmentBonus);
          userEvidence.push('System timestamp timezone corroborates client geographic longitude.');
        }

        estimatedUserLocation = {
          country: cCountry,
          countryCode: cGeo?.countryCode || clientSubmissionHop.countryCode || null,
          region: cGeo?.region || clientSubmissionHop.region || null,
          city: cCity,
          latitude: cLat,
          longitude: cLon,
          accuracyRadiusKm: clientNetwork.accuracyEstimateKm,
          confidence: Math.max(10, Math.min(95, userConfidence)),
          confidenceLevel: getConfidenceLevel(userConfidence),
          networkType: clientNetwork.networkType,
          asn: clientSubmissionHop.asn || cGeo?.asn || null,
          isp: clientSubmissionHop.isp || cGeo?.isp || null,
          organization: cGeo?.org || clientSubmissionHop.organization || null,
          evidence: userEvidence,
          limitations: userLimitations,
          sourceSignals: ['Client Submission Header (X-Originating-IP)', 'Consumer Broadband/Mobile ISP'],
          hypothesisType: 'USER_ESTIMATE',
        };
      } else {
        // Corporate / Educational / Default
        let userConfidence = clientNetwork.networkType === 'EDUCATIONAL' ? 80 : 70;
        const userEvidence: string[] = [
          `Client submission header (X-Originating-IP) recorded enterprise/campus network: ${clientSubmissionHop.organization || clientSubmissionHop.isp || 'Enterprise ASN'}.`,
          `Resolved submission facility: ${cCity ? cCity + ', ' : ''}${cCountry}.`,
        ];
        const userLimitations: string[] = [
          'Corporate network may route employee client sessions through centralized headquarter egress.',
          'Client submission header was inserted by upstream webmail or submission MTA.',
        ];

        estimatedUserLocation = {
          country: cCountry,
          countryCode: cGeo?.countryCode || clientSubmissionHop.countryCode || null,
          region: cGeo?.region || clientSubmissionHop.region || null,
          city: cCity,
          latitude: cLat,
          longitude: cLon,
          accuracyRadiusKm: clientNetwork.accuracyEstimateKm,
          confidence: userConfidence,
          confidenceLevel: getConfidenceLevel(userConfidence),
          networkType: clientNetwork.networkType,
          asn: clientSubmissionHop.asn || cGeo?.asn || null,
          isp: clientSubmissionHop.isp || cGeo?.isp || null,
          organization: cGeo?.org || clientSubmissionHop.organization || null,
          evidence: userEvidence,
          limitations: userLimitations,
          sourceSignals: ['Client Submission Header (X-Originating-IP)', 'Enterprise Network'],
          hypothesisType: 'USER_ESTIMATE',
        };
      }

      // If sending infrastructure is in a different country, add competing hypothesis
      if (sendingInfrastructure && sendingInfrastructure.country && sendingInfrastructure.country !== estimatedUserLocation.country) {
        competingHypotheses.push({
          country: sendingInfrastructure.country,
          countryCode: sendingInfrastructure.countryCode,
          region: sendingInfrastructure.region,
          city: sendingInfrastructure.city,
          latitude: sendingInfrastructure.latitude,
          longitude: sendingInfrastructure.longitude,
          accuracyRadiusKm: sendingInfrastructure.accuracyRadiusKm,
          confidence: 30,
          confidenceLevel: 'LOW',
          networkType: sendingInfrastructure.networkType,
          evidence: [`Outbound transport relay routed from ${sendingInfrastructure.city ? sendingInfrastructure.city + ', ' : ''}${sendingInfrastructure.country} (${infraNetwork.providerCategory}).`],
          limitations: ['Transmitting mail server differs from client submission origin.'],
          sourceSignals: ['Transport Origin Relay'],
          hypothesisType: 'COMPETING',
        });
      }
    } else if (!sendingInfrastructure || !sendingInfrastructure.country) {
      // Inconclusive / No public evidence
      estimatedUserLocation = {
        country: null,
        countryCode: null,
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        accuracyRadiusKm: 0,
        confidence: 0,
        confidenceLevel: 'VERY_LOW',
        networkType: 'UNKNOWN',
        evidence: ['No public routable transport headers detected.'],
        limitations: ['Insufficient evidence to formulate user location hypothesis.'],
        sourceSignals: ['None'],
        hypothesisType: 'USER_ESTIMATE',
      };
    } else if (infraNetwork.isVpnOrTor) {
      // VPN / TOR CASE: Masked user location
      estimatedUserLocation = {
        country: `${sendingInfrastructure.country} (VPN/Proxy Egress)`,
        countryCode: sendingInfrastructure.countryCode,
        region: sendingInfrastructure.region,
        city: sendingInfrastructure.city,
        latitude: sendingInfrastructure.latitude,
        longitude: sendingInfrastructure.longitude,
        accuracyRadiusKm: 2500,
        confidence: 20,
        confidenceLevel: 'LOW',
        networkType: infraNetwork.networkType,
        asn: sendingInfrastructure.asn,
        isp: sendingInfrastructure.isp,
        organization: sendingInfrastructure.organization,
        evidence: [
          `Origin IP ${sendingInfrastructure.ip} is a known ${infraNetwork.providerCategory} gateway.`,
        ],
        limitations: [
          'Sender utilized an anonymizing proxy/VPN tunnel to obfuscate true physical location.',
          'Coordinates reflect egress server, not user physical coordinates.',
        ],
        sourceSignals: ['VPN/Tor Exit Gateway'],
        hypothesisType: 'USER_ESTIMATE',
      };
    } else if (infraNetwork.isCloudOrHosting) {
      // CLOUD HOSTING CASE: The mail originated from AWS/GCP/Azure/Hetzner datacenter!
      // DO NOT attribute physical user location to the cloud datacenter!
      let userConfidence = 15;
      const userEvidence: string[] = [
        `Sending mail server is hosted in ${sendingInfrastructure.city ? sendingInfrastructure.city + ', ' : ''}${sendingInfrastructure.country} (${infraNetwork.providerCategory}).`,
      ];
      const userLimitations: string[] = [
        `Public cloud hosting provider (${infraNetwork.providerCategory}) identified. Cloud mail relays cannot be equated to the physical location of the sender.`,
        'Physical user location is completely decoupled from cloud hosting facility.',
      ];

      // If timezone suggests another region, add competing hypothesis
      if (timezoneCheck.hasTimezoneMismatch && timezoneCheck.headerTimezoneOffsetHours !== undefined) {
        const sign = timezoneCheck.headerTimezoneOffsetHours >= 0 ? '+' : '';
        competingHypotheses.push({
          country: `Timezone UTC${sign}${timezoneCheck.headerTimezoneOffsetHours} Region`,
          countryCode: null,
          region: `Solar Longitude ~${Math.round(timezoneCheck.headerTimezoneOffsetHours * 15)}°`,
          city: null,
          latitude: null,
          longitude: null,
          accuracyRadiusKm: 3000,
          confidence: 45,
          confidenceLevel: 'LOW',
          networkType: 'UNKNOWN',
          evidence: [
            `Sender's mail client clock is configured for UTC${sign}${timezoneCheck.headerTimezoneOffsetHours}.`,
            'Personal computers typically reflect local system time unless overridden.',
          ],
          limitations: ['Clock timezone can be manually spoofed in email client settings.'],
          sourceSignals: ['Date Header Timezone Offset'],
          hypothesisType: 'COMPETING',
        });
      }

      competingHypotheses.push({
        country: sendingInfrastructure.country,
        countryCode: sendingInfrastructure.countryCode,
        region: sendingInfrastructure.region,
        city: sendingInfrastructure.city,
        latitude: sendingInfrastructure.latitude,
        longitude: sendingInfrastructure.longitude,
        accuracyRadiusKm: 1500,
        confidence: 25,
        confidenceLevel: 'LOW',
        networkType: 'CLOUD',
        evidence: [
          `Outbound SMTP transport relayed from ${infraNetwork.providerCategory} in ${sendingInfrastructure.country}.`,
        ],
        limitations: ['Sender may reside in any country while renting remote virtual cloud servers.'],
        sourceSignals: ['Cloud Mail Relay Infrastructure'],
        hypothesisType: 'COMPETING',
      });

      estimatedUserLocation = {
        country: 'Inconclusive (Cloud Mail Relay)',
        countryCode: null,
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        accuracyRadiusKm: 5000,
        confidence: userConfidence,
        confidenceLevel: 'VERY_LOW',
        networkType: infraNetwork.networkType,
        asn: sendingInfrastructure.asn,
        isp: sendingInfrastructure.isp,
        organization: sendingInfrastructure.organization,
        evidence: userEvidence,
        limitations: userLimitations,
        sourceSignals: ['Transport Origin Relay (Cloud)'],
        hypothesisType: 'USER_ESTIMATE',
      };
    } else if (infraNetwork.isResidentialOrMobile) {
      // RESIDENTIAL / MOBILE CASE: Strong correlation with end-user location!
      let userConfidence = infraNetwork.networkType === 'RESIDENTIAL' ? 80 : 75;
      const userEvidence: string[] = [
        `Origin IP ${sendingInfrastructure.ip} belongs to consumer broadband/mobile network (${infraNetwork.providerCategory}).`,
        `Geographic location resolved to ${sendingInfrastructure.city ? sendingInfrastructure.city + ', ' : ''}${sendingInfrastructure.country}.`,
      ];
      const userLimitations: string[] = [
        'Consumer IP geolocation is accurate to metropolitan area, not specific physical dwelling.',
      ];

      if (timezoneCheck.hasTimezoneMismatch) {
        userConfidence -= GEO_ATTRIBUTION_WEIGHTS.timezoneMismatchPenalty;
        userLimitations.push('Timezone discrepancy reduces location attribution certainty.');
      } else {
        userConfidence = Math.min(95, userConfidence + GEO_ATTRIBUTION_WEIGHTS.timezoneAlignmentBonus);
        userEvidence.push('System timestamp timezone corroborates geographic longitude.');
      }

      if (historical.hasHistoricalProfile && !historical.isDeviatingFromProfile) {
        userConfidence = Math.min(95, userConfidence + GEO_ATTRIBUTION_WEIGHTS.historicalProfileAlignmentBonus);
        userEvidence.push(`Consistent with ${historical.priorCasesCount} historical transmissions from this sender.`);
      }

      estimatedUserLocation = {
        country: sendingInfrastructure.country,
        countryCode: sendingInfrastructure.countryCode,
        region: sendingInfrastructure.region,
        city: sendingInfrastructure.city,
        latitude: sendingInfrastructure.latitude,
        longitude: sendingInfrastructure.longitude,
        accuracyRadiusKm: infraNetwork.accuracyEstimateKm,
        confidence: Math.max(10, Math.min(95, userConfidence)),
        confidenceLevel: getConfidenceLevel(userConfidence),
        networkType: infraNetwork.networkType,
        asn: sendingInfrastructure.asn,
        isp: sendingInfrastructure.isp,
        organization: sendingInfrastructure.organization,
        evidence: userEvidence,
        limitations: userLimitations,
        sourceSignals: ['Consumer Broadband/Mobile ISP', 'Transport Hop Sequence'],
        hypothesisType: 'USER_ESTIMATE',
      };
    } else {
      // CORPORATE / EDUCATIONAL / DEFAULT
      let userConfidence = infraNetwork.networkType === 'EDUCATIONAL' ? 75 : 65;
      const userEvidence: string[] = [
        `Origin IP belongs to enterprise/organization network: ${sendingInfrastructure.organization || sendingInfrastructure.isp || 'Corporate ASN'}.`,
        `Resolved facility location: ${sendingInfrastructure.city ? sendingInfrastructure.city + ', ' : ''}${sendingInfrastructure.country}.`,
      ];
      const userLimitations: string[] = [
        'Corporate mail servers may route employee traffic through centralized headquarters or branch VPNs.',
      ];

      estimatedUserLocation = {
        country: sendingInfrastructure.country,
        countryCode: sendingInfrastructure.countryCode,
        region: sendingInfrastructure.region,
        city: sendingInfrastructure.city,
        latitude: sendingInfrastructure.latitude,
        longitude: sendingInfrastructure.longitude,
        accuracyRadiusKm: infraNetwork.accuracyEstimateKm,
        confidence: userConfidence,
        confidenceLevel: getConfidenceLevel(userConfidence),
        networkType: infraNetwork.networkType,
        asn: sendingInfrastructure.asn,
        isp: sendingInfrastructure.isp,
        organization: sendingInfrastructure.organization,
        evidence: userEvidence,
        limitations: userLimitations,
        sourceSignals: ['Enterprise Mail Infrastructure'],
        hypothesisType: 'USER_ESTIMATE',
      };
    }

    // Apply impossible travel penalty if detected
    if (impossibleTravelDetected && estimatedUserLocation && estimatedUserLocation.confidence > 0) {
      estimatedUserLocation.confidence = Math.max(10, estimatedUserLocation.confidence - GEO_ATTRIBUTION_WEIGHTS.impossibleTravelPenalty);
      estimatedUserLocation.confidenceLevel = getConfidenceLevel(estimatedUserLocation.confidence);
      estimatedUserLocation.limitations.push('Impossible travel velocity detected between route endpoints; certainty significantly degraded.');
    }

    // Overall confidence synthesis
    const overallConfidence = estimatedUserLocation ? estimatedUserLocation.confidence : (sendingInfrastructure ? 50 : 0);
    const overallConfidenceLevel = getConfidenceLevel(overallConfidence);

    return {
      sendingInfrastructure,
      interactionLocation,
      estimatedUserLocation,
      competingHypotheses,
      anomalies,
      limitations,
      overallConfidence,
      overallConfidenceLevel,
      trackingEventsCount: trackingEvents.length,
      lastInteractionAt: trackingEvents.length > 0 ? trackingEvents[trackingEvents.length - 1].timestamp : undefined,
      impossibleTravelDetected,
      scoringWeightsSnapshot: GEO_ATTRIBUTION_WEIGHTS,
    };
  }
}
