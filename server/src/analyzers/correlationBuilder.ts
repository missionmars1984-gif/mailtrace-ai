import type {
  CorrelationGraph,
  GraphNode,
  GraphEdge,
  IOCItem,
  EmailAddressInfo,
  ParsedUrl,
  ParsedAttachment,
  RouteHop,
  IdentityAnalysis,
} from '../types/index.js';

export class CorrelationBuilder {
  static build(params: {
    caseId: string;
    from: EmailAddressInfo;
    identity: IdentityAnalysis;
    urls: ParsedUrl[];
    attachments: ParsedAttachment[];
    hops: RouteHop[];
  }): { graph: CorrelationGraph; iocs: IOCItem[] } {
    const { caseId, from, identity, urls, attachments, hops } = params;
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const nodeIds = new Set<string>();

    const addNode = (node: GraphNode) => {
      if (!nodeIds.has(node.id)) {
        nodeIds.add(node.id);
        nodes.push(node);
      }
    };

    // 1. Root Email Node
    const emailNodeId = `email-${caseId}`;
    addNode({
      id: emailNodeId,
      label: `Email (${caseId})`,
      type: 'email',
    });

    // 2. Sender Node
    const senderNodeId = `sender-${from.address}`;
    addNode({
      id: senderNodeId,
      label: from.address,
      type: 'sender',
      riskLevel: identity.consistency === 'LOW' ? 'HIGH' : (identity.consistency === 'MEDIUM' ? 'MEDIUM' : 'LOW'),
    });
    edges.push({ source: emailNodeId, target: senderNodeId, label: 'sent_by' });

    // 3. Sender Domain Node
    const senderDomain = identity.claimed.domain;
    if (senderDomain) {
      const domainNodeId = `domain-${senderDomain}`;
      addNode({
        id: domainNodeId,
        label: senderDomain,
        type: 'domain',
        riskLevel: identity.lookalikeDomain ? 'HIGH' : 'LOW',
      });
      edges.push({ source: senderNodeId, target: domainNodeId, label: 'domain_of' });
    }

    // 4. Origin Route Hop (IP -> ASN -> Geo)
    const originHop = hops.length > 0 ? hops[hops.length - 1] : undefined;
    if (originHop && originHop.ip) {
      const ipNodeId = `ip-${originHop.ip}`;
      addNode({
        id: ipNodeId,
        label: originHop.ip,
        type: 'ip',
        riskLevel: originHop.geo?.org?.toLowerCase().includes('tor') ? 'HIGH' : 'LOW',
      });
      edges.push({ source: emailNodeId, target: ipNodeId, label: 'relayed_from' });

      if (originHop.geo?.asn) {
        const asnNodeId = `asn-${originHop.geo.asn}`;
        addNode({
          id: asnNodeId,
          label: `${originHop.geo.asn} (${originHop.geo.org || 'Unknown Org'})`,
          type: 'asn',
        });
        edges.push({ source: ipNodeId, target: asnNodeId, label: 'routed_by' });

        if (originHop.geo?.country) {
          const geoNodeId = `geo-${originHop.geo.country.replace(/\s+/g, '_')}`;
          addNode({
            id: geoNodeId,
            label: `${originHop.geo.city || ''}, ${originHop.geo.country}`.trim(),
            type: 'geo',
          });
          edges.push({ source: asnNodeId, target: geoNodeId, label: 'located_at' });
        }
      }
    }

    // 5. URLs -> Domains
    for (const [idx, u] of urls.slice(0, 5).entries()) {
      const urlNodeId = `url-${idx}-${u.domain}`;
      addNode({
        id: urlNodeId,
        label: u.url.length > 35 ? u.url.substring(0, 32) + '...' : u.url,
        type: 'url',
        riskLevel: u.riskLevel,
      });
      edges.push({ source: emailNodeId, target: urlNodeId, label: 'contains_link' });

      const urlDomainId = `domain-${u.domain}`;
      addNode({
        id: urlDomainId,
        label: u.domain,
        type: 'domain',
        riskLevel: u.riskLevel,
      });
      edges.push({ source: urlNodeId, target: urlDomainId, label: 'resolves_to' });
    }

    // 6. Attachments -> Hashes
    for (const [idx, att] of attachments.entries()) {
      const attNodeId = `att-${idx}-${att.filename}`;
      addNode({
        id: attNodeId,
        label: att.filename,
        type: 'attachment',
        riskLevel: att.isDangerous ? 'HIGH' : (att.isMacro ? 'MEDIUM' : 'LOW'),
      });
      edges.push({ source: emailNodeId, target: attNodeId, label: 'attached_file' });

      if (att.sha256) {
        const hashNodeId = `hash-${att.sha256.substring(0, 16)}`;
        addNode({
          id: hashNodeId,
          label: `${att.sha256.substring(0, 16)}...`,
          type: 'hash',
        });
        edges.push({ source: attNodeId, target: hashNodeId, label: 'sha256' });
      }
    }

    // Extract IOC items
    const iocs: IOCItem[] = [];

    // Email addresses
    iocs.push({
      type: 'EMAIL',
      value: from.address,
      context: `Claimed Sender (${from.name || 'No Display Name'})`,
      severity: identity.consistency === 'LOW' ? 'HIGH' : 'LOW',
    });

    if (identity.observed.replyTo && identity.observed.replyTo !== from.address) {
      iocs.push({
        type: 'EMAIL',
        value: identity.observed.replyTo,
        context: 'Reply-To Diversion Destination',
        severity: 'HIGH',
      });
    }

    if (identity.observed.returnPath && identity.observed.returnPath !== from.address) {
      iocs.push({
        type: 'EMAIL',
        value: identity.observed.returnPath,
        context: 'Envelope Return-Path Sender',
        severity: 'MEDIUM',
      });
    }

    // Domains
    if (senderDomain) {
      iocs.push({
        type: 'DOMAIN',
        value: senderDomain,
        context: 'Sender Domain',
        severity: identity.lookalikeDomain ? 'HIGH' : 'LOW',
      });
    }

    for (const u of urls) {
      iocs.push({
        type: 'URL',
        value: u.url,
        context: `Extracted Body Link (${u.protocol.toUpperCase()})`,
        severity: u.riskLevel,
      });
      if (u.domain && u.domain !== senderDomain) {
        iocs.push({
          type: 'DOMAIN',
          value: u.domain,
          context: 'Embedded Link Host',
          severity: u.riskLevel,
        });
      }
    }

    // IPs
    for (const h of hops) {
      if (h.ip && !h.isPrivate) {
        iocs.push({
          type: 'IP',
          value: h.ip,
          context: `Hop #${h.hopNumber} (${h.geo?.org || 'Public Relay'})`,
          severity: h.geo?.org?.toLowerCase().includes('tor') ? 'HIGH' : 'LOW',
        });
      }
    }

    // Attachments & Hashes
    for (const att of attachments) {
      iocs.push({
        type: 'ATTACHMENT',
        value: att.filename,
        context: `Payload (${(att.size / 1024).toFixed(1)} KB, ${att.contentType})`,
        severity: att.isDangerous ? 'HIGH' : (att.isMacro ? 'MEDIUM' : 'LOW'),
      });
      if (att.sha256) {
        iocs.push({
          type: 'HASH',
          value: att.sha256,
          context: `SHA-256 for ${att.filename}`,
          severity: att.isDangerous ? 'HIGH' : 'LOW',
        });
      }
    }

    return { graph: { nodes, edges }, iocs };
  }
}
