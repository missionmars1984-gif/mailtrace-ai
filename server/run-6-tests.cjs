const { runAnalysisPipeline } = require('./dist/routes/api.js');

const testEmails = [
  {
    category: '1. Credential phishing',
    rawEmail: `Received: from mail-relay.hostile-net.org ([198.51.100.42]) by mx.company.com with ESMTP id cred_01; Thu, 03 Sep 2026 09:00:00 +0000
From: "Microsoft 365 Security" <security-alerts@m365-verify-portal.top>
To: employee@company.com
Subject: Action required: Unusual sign-in activity
Date: Thu, 03 Sep 2026 09:00:00 +0000
Authentication-Results: mx.company.com; spf=fail; dkim=fail; dmarc=fail

Dear Customer,

We detected abnormal login attempts targeting your corporate Microsoft 365 account.
Please verify your password immediately to retain account access:
http://198.51.100.42/auth/login.php?user=employee@company.com

Your account will be suspended within 24 hours without verification.`,
  },
  {
    category: '2. BEC/payment fraud',
    rawEmail: `Received: from mail-relay.public-webmail.com ([209.85.220.41]) by mx.company.com with ESMTP id bec_01; Thu, 03 Sep 2026 09:00:00 +0000
From: "David Morgan" <david.morgan@gmail.com>
To: finance@company.com
Reply-To: david.morgan.finance@external-mail.example
Subject: Confidential — Orion payment
Date: Thu, 03 Sep 2026 09:00:00 +0000

Hi Team,

I am in an urgent meeting and cannot take calls.
Please initiate a confidential wire transfer of $45,000 for the Orion project before 3 PM cutoff today.
Keep this strictly confidential between us until the transaction settles.

David Morgan
Chief Executive Officer`,
  },
  {
    category: '3. Subtle phishing',
    rawEmail: `Received: from relay-external.cloud-share.biz ([185.190.140.12]) by mx.company.com with ESMTP id sub_01; Thu, 03 Sep 2026 09:00:00 +0000
From: "Microsoft Account Team" <account-team@microsoft-security.example>
To: employee@company.com
Subject: Review your recent account activity
Date: Thu, 03 Sep 2026 09:00:00 +0000

Hello,

We recently noticed unusual activity associated with your single sign-on profile.
Please review your recent account activity and confirm your security settings:
https://login.microsoft-security.example/session/verify?id=99281

Thank you,
Microsoft Account Team`,
  },
  {
    category: '4. Legitimate IT email',
    rawEmail: `Received: from mail.company.com ([192.0.2.10]) by mx.company.com with ESMTP id legit_01; Thu, 03 Sep 2026 09:00:00 +0000
From: "IT Service Desk" <it@company.com>
To: employee@company.com
Reply-To: it@company.com
Subject: Scheduled maintenance — Microsoft 365 services
Date: Thu, 03 Sep 2026 09:00:00 +0000
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass

Hi,

The IT team will be performing scheduled maintenance on our Microsoft 365 services this Saturday between 1:00 AM and 3:00 AM UTC.
No action is required on your part. Systems will remain accessible with brief intermittent interruptions.

Best regards,
IT Service Desk
TargetCorp`,
  },
  {
    category: '5. Bank-account-change fraud',
    rawEmail: `Received: from mail.apexconsulting.example ([198.51.100.99]) by mx.company.com with ESMTP id bank_01; Thu, 03 Sep 2026 09:00:00 +0000
From: "Apex Consulting Accounts" <accounts@apexconsulting.example>
To: finance@company.com
CC: procurement@company.com
Reply-To: accounts@apexconsulting.example
Subject: RE: Invoice INV-39472 — August Services
Date: Thu, 03 Sep 2026 09:00:00 +0000

Hi Finance Team,

Thanks for confirming receipt of invoice INV-39472.

We've recently moved our receivables processing to a new banking provider. Please use the updated remittance details included with the invoice when arranging payment.

Invoice: INV-39472
Amount: $14,820.00
Due date: September 5, 2026

Updated invoice:
https://apexconsulting.example/invoices/INV-39472

Please confirm once payment has been scheduled so we can update our records.

Regards,
Jennifer Lee
Accounts Receivable
Apex Consulting`,
  },
  {
    category: '6. Suspicious attachment',
    rawEmail: `Received: from mail.company.com ([192.0.2.10]) by mx.company.com with ESMTP id hr_att_01; Thu, 03 Sep 2026 09:00:00 +0000
From: "TargetCorp Human Resources" <hr@company.com>
To: employee@company.com
Subject: September holiday schedule & updated policy
Date: Thu, 03 Sep 2026 09:00:00 +0000
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_HR_001"

------=_Part_HR_001
Content-Type: text/plain; charset="UTF-8"

Hi,

Please find the September holiday schedule and updated policy guide attached.
Review the file to ensure your team's coverage is properly scheduled.

Regards,
Human Resources
------=_Part_HR_001
Content-Type: application/x-msdownload; name="September_Schedule_Update.pdf.exe"
Content-Disposition: attachment; filename="September_Schedule_Update.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA=
------=_Part_HR_001--`,
  },
];

async function run() {
  console.log('================================================================');
  console.log('   EVALUATING 6 EXACT TEST CATEGORIES AFTER FIXES');
  console.log('================================================================\n');

  const summaryResults = [];

  for (const test of testEmails) {
    console.log(`\n>>> RUNNING TEST: ${test.category} ...`);
    const result = await runAnalysisPipeline(test.rawEmail);

    summaryResults.push({
      category: test.category,
      subject: result.metadata.subject,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      classification: result.classification,
      componentScores: result.scoreBreakdown?.componentScores,
    });
  }

  console.log('\n================================================================');
  console.log('   FINAL COMPONENT SCORES SUMMARY TABLE');
  console.log('================================================================');
  for (const r of summaryResults) {
    console.log(`\n[${r.category}]`);
    console.log(`  Final Risk Score: ${r.riskScore} / 100 (${r.riskLevel} - ${r.classification})`);
    console.log('  Component Scores:', JSON.stringify(r.componentScores, null, 2));
  }
}

run().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
