import type { ParsedAttachment, SecurityFinding } from '../types/index.js';
import { ModelE_AttachmentModel, type AttachmentModelOutput } from '../models/attachmentModel.js';

export class AttachmentAnalyzer {
  static analyze(rawAttachments: Array<{
    filename?: string;
    contentType?: string;
    size?: number;
    content?: Buffer;
    sha256?: string;
  }>): { attachments: ParsedAttachment[]; findings: SecurityFinding[]; attachmentRisk: number | null } {
    const res: AttachmentModelOutput = ModelE_AttachmentModel.analyze(rawAttachments);
    return {
      attachments: res.parsedAttachments,
      findings: res.findings,
      attachmentRisk: res.attachmentRisk,
    };
  }
}
