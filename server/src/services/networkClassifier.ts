import type { NetworkClassificationType } from '../types/index.js';

export interface NetworkClassificationResult {
  networkType: NetworkClassificationType;
  providerCategory: string;
  isCloudOrHosting: boolean;
  isPrivacyRelayOrProxy: boolean;
  isVpnOrTor: boolean;
  isResidentialOrMobile: boolean;
  isSecurityScanner: boolean;
  accuracyEstimateKm: number;
  maxUserLocationConfidence: number;
  detectedIntermediary: string | null;
  indicators: string[];
}

export class NetworkClassifier {
  /**
   * Evaluates network intelligence (ASN, Org, ISP, IP, User-Agent) to determine
   * the infrastructure tier, intermediary presence, and realistic accuracy radius.
   */
  static classify(params: {
    ip?: string;
    asn?: string | null;
    org?: string | null;
    isp?: string | null;
    userAgent?: string | null;
    hostname?: string | null;
  }): NetworkClassificationResult {
    const asn = (params.asn || '').toUpperCase().trim();
    const org = (params.org || '').toLowerCase().trim();
    const isp = (params.isp || '').toLowerCase().trim();
    const ua = (params.userAgent || '').toLowerCase().trim();
    const host = (params.hostname || '').toLowerCase().trim();
    const combined = `${asn} ${org} ${isp} ${host}`;

    const indicators: string[] = [];

    // 1. Check for Apple Mail Privacy Protection (MPP) / Apple Private Relay
    const isAppleMppUa = ua.includes('mozilla/5.0') && ua.includes('applewebkit') && !ua.includes('chrome') && !ua.includes('safari/');
    const isAppleNetwork =
      combined.includes('apple private relay') ||
      combined.includes('icloud private relay') ||
      combined.includes('cloud-apple') ||
      (asn === 'AS54113' && org.includes('apple')) ||
      (asn === 'AS13335' && org.includes('apple'));

    if (isAppleNetwork || (isAppleMppUa && (combined.includes('cloudflare') || combined.includes('fastly') || combined.includes('apple')))) {
      indicators.push('Apple Mail Privacy Protection (MPP) / iCloud Private Relay identified');
      return {
        networkType: 'PRIVACY_RELAY',
        providerCategory: 'Apple Mail Privacy Protection (iCloud Private Relay)',
        isCloudOrHosting: false,
        isPrivacyRelayOrProxy: true,
        isVpnOrTor: false,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 5000,
        maxUserLocationConfidence: 5,
        detectedIntermediary: 'Apple MPP Proxy',
        indicators,
      };
    }

    // 2. Check for Google Image Proxy
    const isGoogleImageProxyUa = ua.includes('googleimageproxy') || ua.includes('ggpht.com') || ua.includes('feedfetcher-google');
    const isGoogleImageProxyHostOrOrg = host.includes('google-image-proxy') || combined.includes('google image proxy');
    const isGoogleNetwork = combined.includes('google llc') || asn === 'AS15169' || asn === 'AS396982';

    if (isGoogleImageProxyUa || isGoogleImageProxyHostOrOrg || (isGoogleNetwork && ua.includes('google'))) {
      indicators.push('Google Image Proxy prefetch service detected (Mountain View / Google CDN)');
      return {
        networkType: 'PROXY',
        providerCategory: 'Google Image Proxy (Gmail Cache)',
        isCloudOrHosting: false,
        isPrivacyRelayOrProxy: true,
        isVpnOrTor: false,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 5000,
        maxUserLocationConfidence: 5,
        detectedIntermediary: 'Google Image Proxy',
        indicators,
      };
    }

    // 3. Check for Email Security Scanners / URL Sandbox Defense
    if (
      combined.includes('proofpoint') ||
      combined.includes('mimecast') ||
      combined.includes('barracuda') ||
      combined.includes('safelinks') ||
      combined.includes('atp-safelinks') ||
      combined.includes('cisco ironport') ||
      combined.includes('trend micro') ||
      ua.includes('mimecast') ||
      ua.includes('proofpoint') ||
      ua.includes('barracuda')
    ) {
      indicators.push('Enterprise secure email gateway / automated URL scanner detected');
      return {
        networkType: 'SECURITY_SCANNER',
        providerCategory: 'Email Security Gateway Scanner',
        isCloudOrHosting: true,
        isPrivacyRelayOrProxy: true,
        isVpnOrTor: false,
        isResidentialOrMobile: false,
        isSecurityScanner: true,
        accuracyEstimateKm: 5000,
        maxUserLocationConfidence: 0,
        detectedIntermediary: 'Security Scanner',
        indicators,
      };
    }

    // 4. Check for Tor Exit Nodes & Anonymizing VPN Services
    const isTor =
      combined.includes('tor exit') ||
      combined.includes('tor relay') ||
      combined.includes('torservers') ||
      combined.includes('the onion router') ||
      combined.includes('artikel10') ||
      combined.includes('artikel 10') ||
      host.includes('tor-exit');

    if (isTor) {
      indicators.push('Public Tor exit node detected');
      return {
        networkType: 'TOR',
        providerCategory: 'Tor Anonymity Network',
        isCloudOrHosting: false,
        isPrivacyRelayOrProxy: true,
        isVpnOrTor: true,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 10000,
        maxUserLocationConfidence: 0,
        detectedIntermediary: 'Tor Exit Node',
        indicators,
      };
    }

    const isCommercialVpn =
      combined.includes('mullvad') ||
      combined.includes('nordvpn') ||
      combined.includes('tefincom') ||
      combined.includes('expressvpn') ||
      combined.includes('surfshark') ||
      combined.includes('private internet access') ||
      combined.includes('protonvpn') ||
      combined.includes('windscribe') ||
      combined.includes('cyberghost') ||
      combined.includes('hidemyass') ||
      combined.includes('ivpn');

    if (isCommercialVpn) {
      indicators.push('Commercial VPN exit infrastructure identified');
      return {
        networkType: 'VPN',
        providerCategory: 'Commercial VPN Service',
        isCloudOrHosting: true,
        isPrivacyRelayOrProxy: true,
        isVpnOrTor: true,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 2000,
        maxUserLocationConfidence: 15,
        detectedIntermediary: 'Commercial VPN Gateway',
        indicators,
      };
    }

    // 5. Check for Major Public Cloud / Datacenter Infrastructure
    const isAws = asn === 'AS16509' || asn === 'AS14618' || asn === 'AS8987' || combined.includes('amazon') || combined.includes('aws');
    const isGcp = asn === 'AS396982' || (asn === 'AS15169' && (combined.includes('google cloud') || combined.includes('datacenter')));
    const isAzure = asn === 'AS8075' || asn === 'AS8068' || asn === 'AS8069' || combined.includes('microsoft-corp') || combined.includes('azure');
    const isDigitalOcean = asn === 'AS14061' || combined.includes('digitalocean');
    const isHetzner = asn === 'AS24940' || combined.includes('hetzner');
    const isOvh = asn === 'AS16276' || combined.includes('ovh');
    const isLinodeAkamai = asn === 'AS63949' || combined.includes('linode');
    const isOracle = asn === 'AS31898' || combined.includes('oracle cloud');
    const isVultr = asn === 'AS20473' || combined.includes('vultr') || combined.includes('choopa');
    const isContabo = asn === 'AS51167' || combined.includes('contabo');
    const isGenericHosting =
      combined.includes('datacenter') ||
      combined.includes('data center') ||
      combined.includes('hosting') ||
      combined.includes('vps') ||
      combined.includes('server') ||
      combined.includes('cloud') ||
      combined.includes('rackspace') ||
      combined.includes('leaseweb') ||
      combined.includes('hostinger');

    if (isAws || isGcp || isAzure || isDigitalOcean || isHetzner || isOvh || isLinodeAkamai || isOracle || isVultr || isContabo || isGenericHosting) {
      let cloudName = 'Cloud / Datacenter Relay';
      if (isAws) cloudName = 'Amazon Web Services (AWS)';
      else if (isGcp) cloudName = 'Google Cloud Platform (GCP)';
      else if (isAzure) cloudName = 'Microsoft Azure Cloud';
      else if (isDigitalOcean) cloudName = 'DigitalOcean Cloud';
      else if (isHetzner) cloudName = 'Hetzner Online Datacenter';
      else if (isOvh) cloudName = 'OVHcloud Infrastructure';
      else if (isLinodeAkamai) cloudName = 'Linode / Akamai Cloud';
      else if (isOracle) cloudName = 'Oracle Cloud Infrastructure';
      else if (isVultr) cloudName = 'Vultr Cloud';
      else if (isContabo) cloudName = 'Contabo Datacenter';

      indicators.push(`Public cloud/hosting facility identified: ${cloudName}`);
      return {
        networkType: 'CLOUD',
        providerCategory: cloudName,
        isCloudOrHosting: true,
        isPrivacyRelayOrProxy: false,
        isVpnOrTor: false,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 1500, // Represents server farm, not human device
        maxUserLocationConfidence: 15,
        detectedIntermediary: null,
        indicators,
      };
    }

    // 6. Check for CDN Infrastructure
    const isCloudflare = asn === 'AS13335' || combined.includes('cloudflare');
    const isFastly = asn === 'AS54113' || combined.includes('fastly');
    const isAkamai = asn === 'AS20940' || combined.includes('akamai');

    if (isCloudflare || isFastly || isAkamai) {
      const cdnName = isCloudflare ? 'Cloudflare Anycast CDN' : isFastly ? 'Fastly Edge Cloud' : 'Akamai Edge Network';
      indicators.push(`Anycast CDN edge node identified: ${cdnName}`);
      return {
        networkType: 'CDN',
        providerCategory: cdnName,
        isCloudOrHosting: true,
        isPrivacyRelayOrProxy: true,
        isVpnOrTor: false,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 2500,
        maxUserLocationConfidence: 10,
        detectedIntermediary: 'Edge CDN',
        indicators,
      };
    }

    // 7. Check for Educational / University Campus Network
    if (
      combined.includes('.edu') ||
      combined.includes('university') ||
      combined.includes('college') ||
      combined.includes('academic') ||
      combined.includes('campus') ||
      combined.includes('géant') ||
      combined.includes('ernet') ||
      combined.includes('janet') ||
      asn === 'AS786' ||
      asn === 'AS112'
    ) {
      indicators.push('Educational / Research Campus Network');
      return {
        networkType: 'EDUCATIONAL',
        providerCategory: 'University / Research Campus Network',
        isCloudOrHosting: false,
        isPrivacyRelayOrProxy: false,
        isVpnOrTor: false,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 25,
        maxUserLocationConfidence: 80,
        detectedIntermediary: null,
        indicators,
      };
    }

    // 8. Check for Mobile / Cellular Carrier Network
    const isMobile =
      combined.includes('cellular') ||
      combined.includes('mobile') ||
      combined.includes('wireless') ||
      combined.includes('lte') ||
      combined.includes('4g') ||
      combined.includes('5g') ||
      combined.includes('jio mobile') ||
      combined.includes('airtel mobile') ||
      combined.includes('t-mobile') ||
      combined.includes('verizon wireless') ||
      combined.includes('mobility') ||
      combined.includes('softbank mobile');

    if (isMobile) {
      indicators.push('Mobile / Cellular Telecom Carrier Subnet');
      return {
        networkType: 'MOBILE',
        providerCategory: 'Mobile / Cellular Carrier',
        isCloudOrHosting: false,
        isPrivacyRelayOrProxy: false,
        isVpnOrTor: false,
        isResidentialOrMobile: true,
        isSecurityScanner: false,
        accuracyEstimateKm: 35,
        maxUserLocationConfidence: 75,
        detectedIntermediary: null,
        indicators,
      };
    }

    // 9. Check for Consumer Residential Broadband ISP
    const isResidential =
      combined.includes('telecom') ||
      combined.includes('broadband') ||
      combined.includes('fios') ||
      combined.includes('cable') ||
      combined.includes('residential') ||
      combined.includes('dsl') ||
      combined.includes('fiber') ||
      combined.includes('ftth') ||
      combined.includes('comcast') ||
      combined.includes('charter') ||
      combined.includes('spectrum') ||
      combined.includes('at&t internet') ||
      combined.includes('centurylink') ||
      combined.includes('deutsche telekom') ||
      combined.includes('british telecommunications') ||
      combined.includes('orange') ||
      combined.includes('vodafone') ||
      combined.includes('jio') ||
      combined.includes('airtel') ||
      combined.includes('singtel') ||
      combined.includes('telstra');

    if (isResidential) {
      indicators.push('Consumer Residential Broadband ISP');
      return {
        networkType: 'RESIDENTIAL',
        providerCategory: 'Consumer Residential ISP',
        isCloudOrHosting: false,
        isPrivacyRelayOrProxy: false,
        isVpnOrTor: false,
        isResidentialOrMobile: true,
        isSecurityScanner: false,
        accuracyEstimateKm: 40,
        maxUserLocationConfidence: 85,
        detectedIntermediary: null,
        indicators,
      };
    }

    // 10. Default / Corporate or Unknown
    if (org || isp) {
      indicators.push('Enterprise / Corporate Autonomous System');
      return {
        networkType: 'CORPORATE',
        providerCategory: 'Enterprise / Corporate Network',
        isCloudOrHosting: false,
        isPrivacyRelayOrProxy: false,
        isVpnOrTor: false,
        isResidentialOrMobile: false,
        isSecurityScanner: false,
        accuracyEstimateKm: 50,
        maxUserLocationConfidence: 70,
        detectedIntermediary: null,
        indicators,
      };
    }

    return {
      networkType: 'UNKNOWN',
      providerCategory: 'Unclassified Network',
      isCloudOrHosting: false,
      isPrivacyRelayOrProxy: false,
      isVpnOrTor: false,
      isResidentialOrMobile: false,
      isSecurityScanner: false,
      accuracyEstimateKm: 1000,
      maxUserLocationConfidence: 30,
      detectedIntermediary: null,
      indicators: ['Unclassified network segment'],
    };
  }
}
