import type { ParsedAttachment, SecurityFinding } from '../types/index.js';
import { ForensicHashService } from '../crypto/forensicHash.js';

export interface RawAttachmentInput {
  filename?: string;
  contentType?: string;
  size?: number;
  content?: Buffer;
  sha256?: string;
}

export interface AttachmentModelOutput {
  attachmentRisk: number | null; // null if no attachments are analyzed (NOT 0)
  attachmentAnalysisStatus: 'available' | 'unavailable' | 'none_present';
  attachmentCount: number;
  dangerousCount: number;
  parsedAttachments: ParsedAttachment[];
  findings: SecurityFinding[];
  modelTier: 'STATIC_PAYLOAD_MODEL';
}

const EXECUTABLE_EXTENSIONS = new Set(['exe', 'scr', 'dll', 'com', 'pif', 'cpl']);
const SCRIPT_EXTENSIONS = new Set(['vbs', 'vbe', 'js', 'jse', 'bat', 'cmd', 'ps1', 'wsf', 'wsh', 'hta', 'sh']);
const MACRO_EXTENSIONS = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm']);
const ARCHIVE_EXTENSIONS = new Set(['zip', 'rar', '7z', 'iso', 'img', 'vhd', 'tar', 'gz', 'bz2']);

export class ModelE_AttachmentModel {
  /**
   * Static, zero-execution forensic inspection of file attachments.
   * Returns null if no attachments are present.
   */
  static analyze(rawAttachments: RawAttachmentInput[]): AttachmentModelOutput {
    if (!rawAttachments || rawAttachments.length === 0) {
      return {
        attachmentRisk: null, // Strictly null when not present
        attachmentAnalysisStatus: 'none_present',
        attachmentCount: 0,
        dangerousCount: 0,
        parsedAttachments: [],
        findings: [],
        modelTier: 'STATIC_PAYLOAD_MODEL',
      };
    }

    const parsedAttachments: ParsedAttachment[] = [];
    const findings: SecurityFinding[] = [];
    let maxRisk = 0;
    let dangerousCount = 0;

    for (const att of rawAttachments) {
      const filename = (att.filename || 'attachment.dat').trim();
      const contentType = (att.contentType || 'application/octet-stream').toLowerCase();
      const size = att.size || (att.content ? att.content.length : 0);
      const sha256 = att.sha256 || (att.content ? ForensicHashService.sha256(att.content) : 'unknown');

      const parts = filename.split('.');
      const extension = parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
      const riskReasons: string[] = [];
      let itemScore = 0;

      // 1. Double Extension Check (e.g. invoice.pdf.exe)
      const isDoubleExtension = parts.length > 2 && (
        EXECUTABLE_EXTENSIONS.has(extension) ||
        SCRIPT_EXTENSIONS.has(extension) ||
        ARCHIVE_EXTENSIONS.has(extension)
      );

      if (isDoubleExtension) {
        itemScore = Math.max(itemScore, 100);
        riskReasons.push(`Deceptive double extension (${filename}) camouflages dangerous executable file type.`);
        findings.push({
          type: 'ATTACHMENT',
          severity: 'CRITICAL',
          title: 'Deceptive Double Extension Camouflage',
          source: 'Attachment model',
          snippet: filename,
          observed: `File possesses multiple extensions terminating in .${extension}`,
          impact: 'Used to mislead desktop users into opening malicious executables believing they are harmless PDFs or office documents.',
        });
      }

      // 2. Executable Extension Check
      const isDangerousExecutable = EXECUTABLE_EXTENSIONS.has(extension);
      if (isDangerousExecutable) {
        itemScore = Math.max(itemScore, 95);
        riskReasons.push(`Standalone executable payload (.${extension}) delivered via email attachment.`);
        findings.push({
          type: 'ATTACHMENT',
          severity: 'CRITICAL',
          title: `Direct Binary Executable (.${extension.toUpperCase()})`,
          source: 'Attachment model',
          snippet: filename,
          observed: `Executable binary extension: .${extension}`,
          impact: 'Direct vehicle for malware drop, Trojan download, or remote access tool (RAT) persistence.',
        });
      }

      // 3. Script Payload Check
      const isScript = SCRIPT_EXTENSIONS.has(extension);
      if (isScript) {
        itemScore = Math.max(itemScore, 92);
        riskReasons.push(`Script file extension (.${extension}) capable of executing arbitrary commands.`);
        findings.push({
          type: 'ATTACHMENT',
          severity: 'CRITICAL',
          title: `Automated Script Payload (.${extension.toUpperCase()})`,
          source: 'Attachment model',
          snippet: filename,
          observed: `Script extension: .${extension}`,
          impact: 'Executes silently via Windows Script Host (WScript) or PowerShell to drop secondary payloads.',
        });
      }

      // 4. Macro-Enabled Office Document
      const isMacro = MACRO_EXTENSIONS.has(extension);
      if (isMacro) {
        itemScore = Math.max(itemScore, 85);
        riskReasons.push(`Macro-enabled Microsoft Office document format (.${extension}).`);
        findings.push({
          type: 'ATTACHMENT',
          severity: 'HIGH',
          title: `Macro-Enabled Office Payload (.${extension.toUpperCase()})`,
          source: 'Attachment model',
          snippet: filename,
          observed: `Macro-capable format: .${extension}`,
          impact: 'Executes VBA macros upon user opening to initiate stage-one downloader activity.',
        });
      }

      // 5. Container & Disk Image Archive Formats
      const isArchive = ARCHIVE_EXTENSIONS.has(extension);
      if (isArchive) {
        if (['iso', 'img', 'vhd'].includes(extension)) {
          itemScore = Math.max(itemScore, 80);
          riskReasons.push(`Disk image archive (.${extension}) used to bypass Mark-of-the-Web (MOTW) protections.`);
          findings.push({
            type: 'ATTACHMENT',
            severity: 'HIGH',
            title: `Disk Image Archive (.${extension.toUpperCase()})`,
            source: 'Attachment model',
            snippet: filename,
            observed: `Container format: .${extension}`,
            impact: 'Commonly employed to evade Mark-of-the-Web inspection upon automatic mounting.',
          });
        } else {
          itemScore = Math.max(itemScore, 45);
        }
      }

      // 6. Magic Bytes / Header Mismatch (e.g. PE header MZ = 0x4D, 0x5A disguised as PDF or TXT)
      if (att.content && att.content.length >= 2) {
        const isPeHeader = att.content[0] === 0x4d && att.content[1] === 0x5a; // "MZ"
        if (isPeHeader && !EXECUTABLE_EXTENSIONS.has(extension)) {
          itemScore = Math.max(itemScore, 98);
          riskReasons.push(`Binary PE header (MZ) detected in file claiming extension .${extension}.`);
          findings.push({
            type: 'ATTACHMENT',
            severity: 'CRITICAL',
            title: 'MIME Type / Binary Header Spoofing (MZ PE File)',
            source: 'Attachment model',
            snippet: filename,
            observed: `Executable PE magic bytes inside .${extension} container`,
            impact: 'Severe obfuscation: Windows executable renamed with benign document extension.',
          });
        }
      }

      const isDangerous = isDoubleExtension || isDangerousExecutable || isScript || isMacro || itemScore >= 75;
      if (isDangerous) dangerousCount++;

      maxRisk = Math.max(maxRisk, itemScore);

      parsedAttachments.push({
        filename,
        extension,
        contentType,
        size,
        sha256,
        isDangerous,
        isDoubleExtension,
        isMacro,
        riskReasons,
      });
    }

    return {
      attachmentRisk: maxRisk,
      attachmentAnalysisStatus: 'available',
      attachmentCount: rawAttachments.length,
      dangerousCount,
      parsedAttachments,
      findings,
      modelTier: 'STATIC_PAYLOAD_MODEL',
    };
  }
}
