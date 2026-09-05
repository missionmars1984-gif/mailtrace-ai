import type { CaseRecord, LocationHypothesis, RouteHop } from '../types/index.js';
import { DatabaseService } from '../db/database.js';

export interface ImpossibleTravelCheckResult {
  isImpossibleTravel: boolean;
  distanceKm: number;
  timeDiffMinutes: number;
  speedKmPerHour: number;
  reason?: string;
}

export interface HistoricalProfileResult {
  hasHistoricalProfile: boolean;
  priorCasesCount: number;
  typicalCountries: string[];
  typicalAsns: string[];
  isDeviatingFromProfile: boolean;
  anomalyDescription?: string;
}

export interface TimezoneCheckResult {
  hasTimezoneMismatch: boolean;
  headerTimezoneOffsetHours?: number;
  expectedTimezoneOffsetHours?: number;
  timezoneDiscrepancyHours: number;
  anomalyDescription?: string;
}

export class LocationProfiler {
  /**
   * Earth radius in kilometers
   */
  private static readonly EARTH_RADIUS_KM = 6371;

  /**
   * Calculates great-circle distance between two coordinates in kilometers using Haversine formula.
   */
  static haversineDistanceKm(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number
  ): number {
    const toRad = (deg: number) => (deg * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(toRad(lat1)) *
        Math.cos(toRad(lat2)) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return Math.round(this.EARTH_RADIUS_KM * c);
  }

  /**
   * Checks whether travel between two locations within a given time interval is physically impossible (> 900 km/h).
   */
  static checkImpossibleTravel(
    loc1: { latitude: number | null; longitude: number | null; timestamp?: string | null; label?: string },
    loc2: { latitude: number | null; longitude: number | null; timestamp?: string | null; label?: string }
  ): ImpossibleTravelCheckResult {
    if (
      typeof loc1.latitude !== 'number' ||
      typeof loc1.longitude !== 'number' ||
      typeof loc2.latitude !== 'number' ||
      typeof loc2.longitude !== 'number' ||
      !loc1.timestamp ||
      !loc2.timestamp
    ) {
      return {
        isImpossibleTravel: false,
        distanceKm: 0,
        timeDiffMinutes: 0,
        speedKmPerHour: 0,
      };
    }

    const t1 = new Date(loc1.timestamp).getTime();
    const t2 = new Date(loc2.timestamp).getTime();
    if (isNaN(t1) || isNaN(t2)) {
      return {
        isImpossibleTravel: false,
        distanceKm: 0,
        timeDiffMinutes: 0,
        speedKmPerHour: 0,
      };
    }

    const diffMinutes = Math.abs(t2 - t1) / (1000 * 60);
    const distanceKm = this.haversineDistanceKm(
      loc1.latitude,
      loc1.longitude,
      loc2.latitude,
      loc2.longitude
    );

    // Minor geo-jitter or same metropolitan area (< 250 km) does not trigger impossible travel
    if (distanceKm < 250) {
      return {
        isImpossibleTravel: false,
        distanceKm,
        timeDiffMinutes: Math.round(diffMinutes),
        speedKmPerHour: diffMinutes > 0 ? Math.round((distanceKm / diffMinutes) * 60) : 0,
      };
    }

    const hours = Math.max(diffMinutes / 60, 0.0167); // minimum 1 minute
    const speedKmPerHour = Math.round(distanceKm / hours);

    // Commercial aircraft maximum cruising speed is ~900 km/h
    if (speedKmPerHour > 900) {
      const reason = `Physically impossible travel detected: ${distanceKm} km traversed in ${Math.round(
        diffMinutes
      )} minutes (~${speedKmPerHour} km/h) between ${loc1.label || 'Point A'} and ${loc2.label || 'Point B'}. Indicates VPN toggling, multiple actors, or proxy hopping.`;

      return {
        isImpossibleTravel: true,
        distanceKm,
        timeDiffMinutes: Math.round(diffMinutes),
        speedKmPerHour,
        reason,
      };
    }

    return {
      isImpossibleTravel: false,
      distanceKm,
      timeDiffMinutes: Math.round(diffMinutes),
      speedKmPerHour,
    };
  }

  /**
   * Compares the current message with historical cases from the same sender domain/address.
   */
  static analyzeHistoricalProfile(
    senderAddress: string,
    currentCountry?: string | null,
    currentAsn?: string | null
  ): HistoricalProfileResult {
    if (!senderAddress) {
      return {
        hasHistoricalProfile: false,
        priorCasesCount: 0,
        typicalCountries: [],
        typicalAsns: [],
        isDeviatingFromProfile: false,
      };
    }

    const domain = senderAddress.includes('@') ? senderAddress.split('@')[1].toLowerCase().trim() : '';
    const historicalCases = DatabaseService.getCasesBySenderDomain(domain);

    if (historicalCases.length < 2) {
      return {
        hasHistoricalProfile: false,
        priorCasesCount: historicalCases.length,
        typicalCountries: [],
        typicalAsns: [],
        isDeviatingFromProfile: false,
      };
    }

    const countryCounts: Record<string, number> = {};
    const asnCounts: Record<string, number> = {};

    for (const c of historicalCases) {
      const country = c.observedOriginRelay?.country || c.observedOriginRelay?.geo?.country;
      const asn = c.observedOriginRelay?.asn || c.observedOriginRelay?.geo?.asn;
      if (country) countryCounts[country] = (countryCounts[country] || 0) + 1;
      if (asn) asnCounts[asn] = (asnCounts[asn] || 0) + 1;
    }

    const typicalCountries = Object.entries(countryCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([country]) => country);

    const typicalAsns = Object.entries(asnCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([asn]) => asn);

    let isDeviating = false;
    let anomalyDescription: string | undefined;

    if (currentCountry && typicalCountries.length > 0 && !typicalCountries.includes(currentCountry)) {
      isDeviating = true;
      anomalyDescription = `Historical sender profile anomaly: Sender domain @${domain} historically routes via [${typicalCountries.slice(0, 2).join(', ')}], but current message originated from unexpected jurisdiction [${currentCountry}].`;
    }

    return {
      hasHistoricalProfile: true,
      priorCasesCount: historicalCases.length,
      typicalCountries,
      typicalAsns,
      isDeviatingFromProfile: isDeviating,
      anomalyDescription,
    };
  }

  /**
   * Parses the Date header timezone offset and checks for consistency against observed location.
   */
  static checkTimezoneDiscrepancy(
    dateHeader?: string,
    observedTimezone?: string | null,
    observedLongitude?: number | null
  ): TimezoneCheckResult {
    if (!dateHeader) {
      return { hasTimezoneMismatch: false, timezoneDiscrepancyHours: 0 };
    }

    // Match RFC 5322 timezone offset, e.g. "+0530", "-0400", "+0000"
    const tzMatch = dateHeader.match(/([+-])(\d{2})(\d{2})/);
    if (!tzMatch) {
      return { hasTimezoneMismatch: false, timezoneDiscrepancyHours: 0 };
    }

    const sign = tzMatch[1] === '+' ? 1 : -1;
    const hours = parseInt(tzMatch[2], 10);
    const minutes = parseInt(tzMatch[3], 10);
    const headerOffsetHours = sign * (hours + minutes / 60);

    // Approximate expected timezone from longitude if timezone string is not parsed (each 15 degrees lon ≈ 1 hour)
    let expectedOffsetHours: number | undefined;
    if (typeof observedLongitude === 'number' && !isNaN(observedLongitude)) {
      expectedOffsetHours = Math.round((observedLongitude / 15) * 2) / 2; // round to nearest half-hour
    }

    if (expectedOffsetHours !== undefined) {
      const discrepancy = Math.abs(headerOffsetHours - expectedOffsetHours);

      // Discrepancy > 4 hours (and header is not simply UTC/GMT +0000 which is standard in automated servers)
      if (discrepancy > 4 && !(headerOffsetHours === 0 && dateHeader.includes('+0000'))) {
        const anomalyDescription = `Timezone discrepancy: Client Date header specifies UTC${headerOffsetHours >= 0 ? '+' : ''}${headerOffsetHours}, whereas physical relay longitude indicates expected solar time UTC${expectedOffsetHours >= 0 ? '+' : ''}${expectedOffsetHours} (~${discrepancy.toFixed(1)}h variance).`;

        return {
          hasTimezoneMismatch: true,
          headerTimezoneOffsetHours: headerOffsetHours,
          expectedTimezoneOffsetHours: expectedOffsetHours,
          timezoneDiscrepancyHours: Math.round(discrepancy),
          anomalyDescription,
        };
      }
    }

    return {
      hasTimezoneMismatch: false,
      headerTimezoneOffsetHours: headerOffsetHours,
      expectedTimezoneOffsetHours: expectedOffsetHours,
      timezoneDiscrepancyHours: 0,
    };
  }
}
