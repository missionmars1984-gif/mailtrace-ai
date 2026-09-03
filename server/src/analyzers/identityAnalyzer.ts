import type {
  EmailAddressInfo,
  AuthenticationResults,
  IdentityAnalysis,
  SecurityFinding,
} from '../types/index.js';
import { ModelC_SenderIdentityModel, type IdentityModelOutput } from '../models/identityModel.js';

export class IdentityAnalyzer {
  static analyze(
    from: EmailAddressInfo,
    replyTo?: EmailAddressInfo,
    returnPath?: string,
    auth?: AuthenticationResults,
    sendingIp?: string
  ): {
    identityAnalysis: IdentityAnalysis;
    findings: SecurityFinding[];
    identityRisk: number;
    identityConsistencyScore: number;
    claimedIdentity: string;
    observedIdentity: string;
  } {
    const res: IdentityModelOutput = ModelC_SenderIdentityModel.analyze({
      from,
      replyTo,
      returnPath,
      auth,
    });

    if (sendingIp) {
      res.identityAnalysis.observed.sendingIp = sendingIp;
    }

    return {
      identityAnalysis: res.identityAnalysis,
      findings: res.findings,
      identityRisk: res.identityRisk,
      identityConsistencyScore: res.identityConsistencyScore,
      claimedIdentity: res.claimedIdentity,
      observedIdentity: res.observedIdentity,
    };
  }
}
