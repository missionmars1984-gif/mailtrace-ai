export interface DemoEmailFixture {
  id: string;
  name: string;
  description: string;
  category: 'Clean' | 'Phishing' | 'BEC' | 'Malware' | 'Impersonation' | 'Legitimate';
  rawEmail: string;
}

export const DEMO_EMAILS: DemoEmailFixture[] = [
  {
    id: 'demo-legitimate',
    name: 'Clean Corporate Email',
    category: 'Clean',
    description: 'Internal project architecture update from verified company domain with valid cryptographic authentication.',
    rawEmail: `Delivered-To: arivera@acmecorp.com
Received: by 2002:a05:6e02:18c1:b0:37a:4211:99a8 with SMTP id x1csp4129881neq;
        Thu, 3 Sep 2026 09:15:22 -0700 (PDT)
Received: from mail-relay.acmecorp.com (mail-relay.acmecorp.com. [209.85.220.41])
        by mx.google.com with ESMTPS id o18-20020a05620a2a1200b0079942a7812asi1982729qkp.42.2026.09.03.09.15.21
        for <arivera@acmecorp.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Sep 2026 09:15:21 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of sjenkins@acmecorp.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=sjenkins@acmecorp.com;
       dkim=pass header.i=@acmecorp.com header.s=google header.b=XyZ1239;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acmecorp.com
From: "Sarah Jenkins" <sjenkins@acmecorp.com>
To: "Alex Rivera" <arivera@acmecorp.com>
Reply-To: <sjenkins@acmecorp.com>
Return-Path: <sjenkins@acmecorp.com>
Subject: Q3 SOC Modernization Architecture Review Notes
Date: Thu, 03 Sep 2026 16:14:00 +0000
Message-ID: <CAB2s-6k91k29f9m1@mail.acmecorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hi Alex,

Thanks for walking the engineering and security team through the Q3 Security Operations Center (SOC) architecture this morning.

I've uploaded the consolidated threat model and telemetry diagrams to our internal engineering wiki here:
https://docs.acmecorp.com/security/soc-review-2026

Next steps:
1. Review the SIEM ingestion pipeline rules.
2. Complete the incident response runbook by Wednesday.

Let me know if you have any questions before the executive sprint planning on Monday.

Best regards,

Sarah Jenkins
Staff Security Engineer, Platform Security
Acme Corp Inc. | https://acmecorp.com
`,
  },
  {
    id: 'demo-phishing',
    name: 'Credential Phishing',
    category: 'Phishing',
    description: 'Urgent account suspension alert with direct numeric IP link, envelope mismatch, and credential harvesting pressure.',
    rawEmail: `Delivered-To: arivera@acmecorp.com
Received: from relay-node4.mailer-dispatch.net (relay-node4.mailer-dispatch.net. [198.51.100.42])
        by mx.acmecorp.com with ESMTP id p4198237912
        for <arivera@acmecorp.com>; Thu, 3 Sep 2026 10:20:11 -0400
Received-SPF: softfail (mx.acmecorp.com: transitioning domain of bounce@newsletter-mailer.org does not designate 198.51.100.42 as permitted sender)
Authentication-Results: mx.acmecorp.com;
       spf=softfail smtp.mailfrom=bounce@newsletter-mailer.org;
       dkim=fail header.i=@m365-verify-portal.com;
       dmarc=fail (p=NONE) header.from=m365-verify-portal.com
From: "Microsoft 365 Security Team" <security-alerts@m365-verify-portal.com>
To: "Alex Rivera" <arivera@acmecorp.com>
Reply-To: <harvest-collector@attacker-inbox.com>
Return-Path: <bounce@newsletter-mailer.org>
Subject: URGENT: Your Microsoft 365 Account Will Be Suspended Within 24 Hours
Date: Thu, 03 Sep 2026 14:19:42 +0000
Message-ID: <20260903141942.88127391@mailer-dispatch.net>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Customer,

URGENT ACTION REQUIRED: We detected abnormal login attempts targeting your corporate Microsoft 365 account.

To safeguard your organization's security perimeter, your account will be suspended within 24 hours unless you complete verification immediately.

Failure to comply will result in immediate closure of your corporate email access and associated cloud documents.

Please log in to keep your account active and confirm your credentials at our secure validation checkpoint:
http://198.51.100.42/auth/login?user=arivera@acmecorp.com

Update your password and re-verify your identity to prevent service interruption.

Thank you for your cooperation,
Microsoft Online Account Security Team
`,
  },
  {
    id: 'demo-bec',
    name: 'CEO / BEC Fraud',
    category: 'BEC',
    description: 'Executive impersonation demanding urgent confidential wire transfer from a mobile pretext over Tor proxy infrastructure.',
    rawEmail: `Delivered-To: arivera@acmecorp.com
Received: from tor-exit-node.privacy-guard.org ([185.220.101.5])
        by mx.acmecorp.com with ESMTP id b881927361
        for <arivera@acmecorp.com>; Thu, 3 Sep 2026 11:04:15 -0400
Received-SPF: pass (mx.acmecorp.com: domain of ceo.david.sterling@gmail.com designates 185.220.101.5 as permitted sender)
Authentication-Results: mx.acmecorp.com;
       spf=pass smtp.mailfrom=ceo.david.sterling@gmail.com;
       dkim=none;
       dmarc=none
From: "David Sterling - CEO" <ceo.david.sterling@gmail.com>
To: "Alex Rivera" <arivera@acmecorp.com>
Reply-To: <executive.wire.settlement@proton.me>
Return-Path: <ceo.david.sterling@gmail.com>
Subject: URGENT & CONFIDENTIAL: Time-sensitive vendor wire transfer settlement
Date: Thu, 03 Sep 2026 15:03:55 +0000
Message-ID: <CALV_88x2-99mK00@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Alex,

Are you at your desk right now?

I am currently in a closed-door board meeting regarding an urgent strategic acquisition and cannot take calls. Please reach me only by email.

We have an outstanding confidential vendor invoice of $48,500 that must be settled today before bank cut-off at 4:00 PM EST. Our partner's remittance address has changed due to international banking compliance audits.

Keep this strictly confidential and do not discuss this with the rest of the finance team until the transaction is closed. 

Please reply immediately so I can send you the updated wire transfer details and banking coordinates.

Thanks,

David Sterling
Chief Executive Officer
Acme Corp Inc.
Sent from my iPad
`,
  },
  {
    id: 'demo-attachment',
    name: 'Suspicious Attachment',
    category: 'Malware',
    description: 'Fake QuickBooks invoice carrying a deceptive double-extension executable (Invoice.pdf.exe) payload.',
    rawEmail: `Delivered-To: arivera@acmecorp.com
Received: from vps-mailer.hostkey-cloud.net ([91.240.118.12])
        by mx.acmecorp.com with ESMTP id m109283746
        for <arivera@acmecorp.com>; Thu, 3 Sep 2026 08:42:01 -0400
Authentication-Results: mx.acmecorp.com;
       spf=fail smtp.mailfrom=nobody@hostkey-vps.ru;
       dkim=none;
       dmarc=fail header.from=invoicing-quickbooks-online.net
From: "QuickBooks Billing Department" <billing@invoicing-quickbooks-online.net>
To: "Alex Rivera" <arivera@acmecorp.com>
Reply-To: <billing-support@fastmail-relay.net>
Return-Path: <nobody@hostkey-vps.ru>
Subject: Overdue Statement - Invoice #INV-892014 Attached
Date: Thu, 03 Sep 2026 12:41:22 +0000
Message-ID: <20260903.124122.INV892@hostkey-cloud.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_89102_1729012"

------=_Part_89102_1729012
Content-Type: text/plain; charset=UTF-8

Dear Valued Customer,

Please find attached your overdue payment receipt and updated billing ledger for Invoice #INV-892014.

Total Balance Due: $3,420.00
Due Date: Immediate

Please review the attached document to verify the itemized breakdown. Failure to remit balance will trigger immediate legal escalation and collection processing.

Sincerely,
QuickBooks Invoicing Support

------=_Part_89102_1729012
Content-Type: application/x-msdownload; name="Invoice_March2026_Details.pdf.exe"
Content-Disposition: attachment; filename="Invoice_March2026_Details.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAsAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
RE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
------=_Part_89102_1729012--
`,
  },
  {
    id: 'demo-lookalike',
    name: 'Lookalike-Domain Phishing',
    category: 'Impersonation',
    description: 'Deceptive typosquatted domain (paypa1-security.com) impersonating PayPal with fake login checkpoint link.',
    rawEmail: `Delivered-To: arivera@acmecorp.com
Received: from out-relay.paypa1-security.com ([45.33.32.156])
        by mx.acmecorp.com with ESMTP id lk99882231
        for <arivera@acmecorp.com>; Thu, 3 Sep 2026 07:11:45 -0400
Authentication-Results: mx.acmecorp.com;
       spf=pass (paypa1-security.com designates 45.33.32.156 as permitted sender);
       dkim=pass header.i=@paypa1-security.com;
       dmarc=pass header.from=paypa1-security.com
From: "PayPal Fraud Prevention" <notifications@paypa1-security.com>
To: "Alex Rivera" <arivera@acmecorp.com>
Reply-To: <disputes@paypa1-security.com>
Return-Path: <service@paypa1-security.com>
Subject: Security Alert: Unauthorized access detected from unknown device
Date: Thu, 03 Sep 2026 11:10:50 +0000
Message-ID: <9921389.12391@paypa1-security.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Customer,

We detected an unauthorized sign-in attempt from a new device in Moscow, Russia:

Device: Linux x86_64 / Firefox 128.0
IP Address: 194.26.29.112
Time: September 3, 2026, 06:58 UTC

If this was not authorized by you, someone may possess your account credentials. You must immediately verify your identity and confirm your password through our secure resolution center:

http://paypa1-security.com/signin/checkpoint?session=sec_99182390182

Failure to secure your profile within 12 hours will trigger permanent account limitation.

Sincerely,
PayPal Security & Risk Operations Team
`,
  },
];
