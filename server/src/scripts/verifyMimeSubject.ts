import { EmailParser } from '../parser/emailParser.js';
import { runAnalysisPipeline } from '../routes/api.js';

interface TestCase {
  id: number;
  name: string;
  raw: string;
  expectedSubject: string;
  expectedHasHeader: boolean;
  verifyFields?: {
    fromAddress?: string;
    toAddress?: string;
    hasReceived?: boolean;
    hasAuth?: boolean;
    hasAttachment?: boolean;
    hasBodyText?: boolean;
    hasBodyHtml?: boolean;
  };
}

const TEST_CASES: TestCase[] = [
  // 1. multipart/alternative
  {
    id: 1,
    name: 'multipart/alternative with standard Subject',
    raw: `From: sender@domain.com
To: recipient@domain.com
Subject: Quarterly Performance Review
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="alt_bnd_123"

--alt_bnd_123
Content-Type: text/plain; charset="UTF-8"

Please find the quarterly performance review details below.

--alt_bnd_123
Content-Type: text/html; charset="UTF-8"

<html><body><p>Please find the quarterly performance review details below.</p></body></html>
--alt_bnd_123--`,
    expectedSubject: 'Quarterly Performance Review',
    expectedHasHeader: true,
    verifyFields: {
      fromAddress: 'sender@domain.com',
      toAddress: 'recipient@domain.com',
      hasBodyText: true,
      hasBodyHtml: true,
    },
  },

  // 2. multipart/mixed
  {
    id: 2,
    name: 'multipart/mixed with standard Subject',
    raw: `From: finance@corp.com
To: accounts@target.com
Subject: Invoice INV-48291 - Payment Update
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix_bnd_456"

--mix_bnd_456
Content-Type: text/plain; charset="UTF-8"

Invoice is attached.

--mix_bnd_456
Content-Type: application/pdf; name="invoice_48291.pdf"
Content-Disposition: attachment; filename="invoice_48291.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrp...
--mix_bnd_456--`,
    expectedSubject: 'Invoice INV-48291 - Payment Update',
    expectedHasHeader: true,
    verifyFields: {
      fromAddress: 'finance@corp.com',
      hasAttachment: true,
    },
  },

  // 3. text/plain
  {
    id: 3,
    name: 'text/plain with Project Review Meeting',
    raw: `From: alice@company.org
To: bob@company.org
Subject: Project Review Meeting
Date: Thu, 04 Sep 2026 10:00:00 +0000
Message-ID: <msg-003@company.org>
Content-Type: text/plain; charset="UTF-8"

Hi Bob, let's meet tomorrow at 10 AM.`,
    expectedSubject: 'Project Review Meeting',
    expectedHasHeader: true,
    verifyFields: {
      fromAddress: 'alice@company.org',
      hasBodyText: true,
    },
  },

  // 4. text/html
  {
    id: 4,
    name: 'text/html with URGENT: Unusual Sign-In Detected',
    raw: `From: security@alerts-security.com
To: user@target.com
Subject: URGENT: Unusual Sign-In Detected
Content-Type: text/html; charset="UTF-8"

<html><body><h2>Security Alert</h2><p>New sign-in from 192.0.2.1</p></body></html>`,
    expectedSubject: 'URGENT: Unusual Sign-In Detected',
    expectedHasHeader: true,
    verifyFields: {
      hasBodyHtml: true,
    },
  },

  // 5. MIME email with attachment
  {
    id: 5,
    name: 'MIME email with attachment',
    raw: `From: hr@target.com
To: employee@target.com
Subject: Updated Contract – September 2026
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="att_boundary"

--att_boundary
Content-Type: text/plain; charset="UTF-8"

Please sign the updated contract.

--att_boundary
Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document
Content-Disposition: attachment; filename="Contract_Sept_2026.docx"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAAA=
--att_boundary--`,
    expectedSubject: 'Updated Contract – September 2026',
    expectedHasHeader: true,
    verifyFields: {
      hasAttachment: true,
    },
  },

  // 6. MIME email with multiple Received headers
  {
    id: 6,
    name: 'MIME email with multiple Received headers and Re: Meeting Tomorrow',
    raw: `Received: from mail-relay2.isp.com ([198.51.100.22]) by mx.target.com with ESMTP id 8821; Thu, 04 Sep 2026 11:00:00 +0000
Received: from mail-client.corp.com ([203.0.113.50]) by mail-relay2.isp.com with ESMTP; Thu, 04 Sep 2026 10:59:00 +0000
From: colleague@partner.com
To: user@target.com
Subject: Re: Meeting Tomorrow
Date: Thu, 04 Sep 2026 11:00:00 +0000
Content-Type: text/plain; charset="UTF-8"

Looking forward to our session tomorrow.`,
    expectedSubject: 'Re: Meeting Tomorrow',
    expectedHasHeader: true,
    verifyFields: {
      hasReceived: true,
    },
  },

  // 7. MIME email with Authentication-Results
  {
    id: 7,
    name: 'MIME email with Authentication-Results and Re: Quarterly Security Review',
    raw: `Received: from relay.sec.org ([192.0.2.77]) by mx.target.com; Thu, 04 Sep 2026 11:05:00 +0000
Authentication-Results: mx.target.com; spf=pass (sender IP 192.0.2.77); dkim=pass; dmarc=pass
From: secops@sec.org
To: user@target.com
Subject: Re: Quarterly Security Review
Content-Type: text/plain; charset="UTF-8"

Audit results are clean.`,
    expectedSubject: 'Re: Quarterly Security Review',
    expectedHasHeader: true,
    verifyFields: {
      hasAuth: true,
    },
  },

  // 8. MIME email with UTF-8 subject
  {
    id: 8,
    name: 'MIME email with raw UTF-8 characters in Subject',
    raw: `From: international@partner.de
To: user@target.com
Subject: Überprüfung der Sicherheitsrichtlinien – Version 2.4
Content-Type: text/plain; charset="UTF-8"

Guten Tag, bitte prüfen Sie das Dokument.`,
    expectedSubject: 'Überprüfung der Sicherheitsrichtlinien – Version 2.4',
    expectedHasHeader: true,
  },

  // 9. MIME email with encoded subject (Base64 & Quoted-Printable)
  {
    id: 9,
    name: 'MIME email with Base64 encoded UTF-8 Subject (=?UTF-8?B?...?=)',
    raw: `From: notifier@service.com
To: user@target.com
Subject: =?UTF-8?B?VXBkYXRlZCBQcm9qZWN0IFJlcG9ydA==?=
Content-Type: text/plain; charset="UTF-8"

The updated project report has been prepared.`,
    expectedSubject: 'Updated Project Report',
    expectedHasHeader: true,
  },
  {
    id: 10,
    name: 'MIME email with Quoted-Printable encoded Subject (=?UTF-8?Q?...?=)',
    raw: `From: billing@vendor.com
To: user@target.com
Subject: =?UTF-8?Q?Invoice_INV-48291_-_Payment_Update?=
Content-Type: text/plain; charset="UTF-8"

Invoice details.`,
    expectedSubject: 'Invoice INV-48291 - Payment Update',
    expectedHasHeader: true,
  },

  // 10. MIME email with folded/long subject
  {
    id: 11,
    name: 'MIME email with multi-line folded Subject header',
    raw: `From: alerts@corp.com
To: user@target.com
Subject: This is a very long subject that may be
 continued onto another header line
Content-Type: text/plain; charset="UTF-8"

Body text.`,
    expectedSubject: 'This is a very long subject that may be continued onto another header line',
    expectedHasHeader: true,
  },

  // 11. MIME email with empty Subject
  {
    id: 12,
    name: 'MIME email with explicit empty Subject header (Subject:)',
    raw: `From: test@empty.com
To: user@target.com
Subject:
Content-Type: text/plain; charset="UTF-8"

Body text with empty subject header.`,
    expectedSubject: '',
    expectedHasHeader: true,
  },
  {
    id: 13,
    name: 'MIME email with explicit empty Subject with spaces (Subject:   )',
    raw: `From: test@empty.com
To: user@target.com
Subject:   
Content-Type: text/plain; charset="UTF-8"

Body text with whitespace subject header.`,
    expectedSubject: '',
    expectedHasHeader: true,
  },

  // 12. MIME email with no Subject header
  {
    id: 14,
    name: 'MIME email with completely absent Subject header',
    raw: `From: nosubject@test.com
To: user@target.com
Date: Thu, 04 Sep 2026 12:00:00 +0000
Content-Type: text/plain; charset="UTF-8"

Body text with no subject header at all.`,
    expectedSubject: '(No Subject)',
    expectedHasHeader: false,
  },

  // 13. Subject in BODY should NOT be confused with Header
  {
    id: 15,
    name: 'Body contains "Subject: Fake Body" but header has "Real Subject"',
    raw: `From: legit@test.com
To: user@target.com
Subject: Real Subject
Content-Type: text/plain; charset="UTF-8"

Hello,
Subject: Fake Body Subject
This should not be used as subject.`,
    expectedSubject: 'Real Subject',
    expectedHasHeader: true,
  },
  {
    id: 16,
    name: 'Body contains "Subject: Fake Body" and header has NO Subject',
    raw: `From: legit@test.com
To: user@target.com
Content-Type: text/plain; charset="UTF-8"

Hello,
Subject: Fake Body Subject
Header has no subject.`,
    expectedSubject: '(No Subject)',
    expectedHasHeader: false,
  },

  // 14. Case-insensitivity: lowercase and uppercase
  {
    id: 17,
    name: 'Lowercase subject: header',
    raw: `From: test@test.com
To: user@target.com
subject: CONFIDENTIAL: Acquisition Payment
Content-Type: text/plain; charset="UTF-8"

Content here.`,
    expectedSubject: 'CONFIDENTIAL: Acquisition Payment',
    expectedHasHeader: true,
  },
  {
    id: 18,
    name: 'Uppercase SUBJECT: header',
    raw: `From: test@test.com
To: user@target.com
SUBJECT: Invoice INV-48291 - Updated Bank Details
Content-Type: text/plain; charset="UTF-8"

Content here.`,
    expectedSubject: 'Invoice INV-48291 - Updated Bank Details',
    expectedHasHeader: true,
  },

  // 15. Leading blank lines / whitespace before first header
  {
    id: 19,
    name: 'Raw email with leading blank lines before headers',
    raw: `

From: test@test.com
To: user@target.com
Subject: Email With Leading Blank Lines
Content-Type: text/plain; charset="UTF-8"

Body here.`,
    expectedSubject: 'Email With Leading Blank Lines',
    expectedHasHeader: true,
  },
];

async function run() {
  console.log('===============================================================');
  console.log('  MAILTRACE RAW MIME EMAIL PARSER — SUBJECT EXTRACTION SUITE  ');
  console.log('===============================================================\n');

  let passed = 0;
  let failed = 0;

  for (const tc of TEST_CASES) {
    try {
      const parsed = await EmailParser.parse(tc.raw);

      const subjectMatch = parsed.subject === tc.expectedSubject;
      const normalizedMatch = parsed.normalized.subject === tc.expectedSubject;

      let otherValid = true;
      if (tc.verifyFields) {
        if (tc.verifyFields.fromAddress && parsed.from.address !== tc.verifyFields.fromAddress) {
          otherValid = false;
        }
        if (tc.verifyFields.toAddress && parsed.to[0]?.address !== tc.verifyFields.toAddress) {
          otherValid = false;
        }
        if (tc.verifyFields.hasReceived && parsed.hops.length === 0) {
          otherValid = false;
        }
        if (tc.verifyFields.hasAttachment && parsed.attachments.length === 0) {
          otherValid = false;
        }
        if (tc.verifyFields.hasBodyText && !parsed.bodyText) {
          otherValid = false;
        }
        if (tc.verifyFields.hasBodyHtml && !parsed.bodyHtml) {
          otherValid = false;
        }
      }

      if (subjectMatch && normalizedMatch && otherValid) {
        console.log(`[PASS] #${tc.id} - ${tc.name}`);
        console.log(`       Subject: "${parsed.subject}"`);
        passed++;
      } else {
        console.error(`[FAIL] #${tc.id} - ${tc.name}`);
        console.error(`       Expected: "${tc.expectedSubject}" | Actual: "${parsed.subject}"`);
        console.error(`       Normalized: "${parsed.normalized.subject}" | OtherValid: ${otherValid}`);
        failed++;
      }
    } catch (err: any) {
      console.error(`[ERROR] #${tc.id} - ${tc.name}:`, err.message);
      failed++;
    }
  }

  // End-to-end Pipeline Test with API
  console.log('\n--- End-to-End Pipeline Verification with runAnalysisPipeline ---');
  const e2eRaw = `From: "Alex Mercer" <alex@cyberops.net>
To: target@corp.com
Subject: =?UTF-8?B?VXBkYXRlZCBQcm9qZWN0IFJlcG9ydA==?=
Date: Thu, 04 Sep 2026 12:30:00 +0000
Message-ID: <e2e-001@cyberops.net>
Content-Type: text/plain; charset="UTF-8"

Hi team, here is the updated project report.`;

  try {
    const caseRecord = await runAnalysisPipeline(e2eRaw);
    console.log('Case Number:', caseRecord.caseNumber);
    console.log('API CaseRecord Subject:', JSON.stringify(caseRecord.subject));
    console.log('API CaseRecord Metadata Subject:', JSON.stringify(caseRecord.metadata.subject));

    if (
      caseRecord.subject === 'Updated Project Report' &&
      caseRecord.metadata.subject === 'Updated Project Report'
    ) {
      console.log('[PASS] Full End-to-End API Pipeline preserves decoded subject!');
      passed++;
    } else {
      console.error('[FAIL] Full End-to-End API Pipeline subject mismatch');
      failed++;
    }
  } catch (err: any) {
    console.error('[ERROR] End-to-End API Pipeline:', err);
    failed++;
  }

  console.log('\n===============================================================');
  console.log(`  RESULTS: ${passed} PASSED / ${failed} FAILED (Total: ${passed + failed})`);
  console.log('===============================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch((e) => {
  console.error('Fatal test error:', e);
  process.exit(1);
});
