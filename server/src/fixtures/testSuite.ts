export interface TestCaseDefinition {
  id: string; // 'A' through 'Q'
  name: string;
  category: string;
  expectedClassification: 'Critical' | 'High Risk' | 'Suspicious' | 'Clean' | 'Low Risk';
  expectedMinRisk: number;
  expectedMaxRisk: number;
  rawEmail: string;
}

export const TEST_SUITE: TestCaseDefinition[] = [
  // ========================================================
  // A. OBVIOUS CREDENTIAL PHISHING
  // ========================================================
  {
    id: 'A',
    name: 'Obvious Credential Phishing - M365 Suspension Lure',
    category: 'Credential Phishing',
    expectedClassification: 'Critical',
    expectedMinRisk: 85,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-relay.hostile-net.org ([198.51.100.42]) by mx.targetcorp.com with ESMTP id m365_001; Thu, 03 Sep 2026 09:12:00 +0000
From: "Microsoft 365 Security Team" <security-update@m365-verify-portal.top>
To: target.user@targetcorp.com
Subject: URGENT: Your Microsoft 365 Account Will Be Suspended Within 24 Hours
Date: Thu, 03 Sep 2026 09:12:00 +0000
Message-ID: <suspension-alert-001@m365-verify-portal.top>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=fail (sender IP 198.51.100.42 not authorized); dkim=fail; dmarc=fail

<html><body>
<h2>Microsoft Security Notice</h2>
<p>Your corporate access has been temporarily restricted due to suspicious activities.</p>
<p><strong>Immediate action required:</strong> You must verify your credentials within 24 hours to prevent immediate account closure.</p>
<p><a href="http://198.51.100.42/auth/login.php?user=target.user@targetcorp.com">Click Here to Verify Your Password and Retain Access</a></p>
<p>Failure to comply will result in permanent deletion of your mailbox and OneDrive files.</p>
</body></html>`,
  },

  // ========================================================
  // B. SUBTLE CREDENTIAL PHISHING
  // ========================================================
  {
    id: 'B',
    name: 'Subtle Credential Phishing - Shared Document Portal',
    category: 'Credential Phishing',
    expectedClassification: 'Critical',
    expectedMinRisk: 75,
    expectedMaxRisk: 95,
    rawEmail: `Received: from relay-external.cloud-share.biz ([185.190.140.12]) by mx.targetcorp.com with ESMTP id doc_002; Thu, 03 Sep 2026 10:15:00 +0000
From: "Cloud Document Service" <notifications@secure-doc-exchange.xyz>
To: target.user@targetcorp.com
Subject: Document Shared: Q3 Performance Summary & Compensation Adjustment
Date: Thu, 03 Sep 2026 10:15:00 +0000
Message-ID: <share-doc-002@secure-doc-exchange.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<p>A confidential document has been securely shared with you.</p>
<p>File: <strong>Q3_Compensation_Plan.pdf</strong> (Encrypted Cloud Storage)</p>
<p>Please <a href="https://login.secure-doc-exchange.xyz/session/verify?id=99281">sign in with your organizational credentials to unlock the encrypted document</a>.</p>
</body></html>`,
  },

  // ========================================================
  // C. SPEAR PHISHING
  // ========================================================
  {
    id: 'C',
    name: 'Spear Phishing - Internal Project Review',
    category: 'Spear Phishing',
    expectedClassification: 'High Risk',
    expectedMinRisk: 65,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-out.freemail-relay.net ([91.240.118.55]) by mx.targetcorp.com with ESMTP id spear_003; Thu, 03 Sep 2026 10:30:00 +0000
From: "Alex Taylor (Project Lead)" <alextaylor.targetcorp@gmail.com>
To: target.user@targetcorp.com
Reply-To: alex.drop.inbox@mailinator.com
Subject: Project Alpha review notes - urgent feedback needed
Date: Thu, 03 Sep 2026 10:30:00 +0000
Message-ID: <spear-003@freemail-relay.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi,

Following up on our Project Alpha milestones. I'm currently traveling and my corporate VPN is down, so reaching out from my personal email.
Please review the attached project checklist and confirm your sections:
https://bit.ly/project-alpha-secure-checkpoint

Let me know once verified.
Alex`,
  },

  // ========================================================
  // D. CEO BEC
  // ========================================================
  {
    id: 'D',
    name: 'CEO BEC - Urgent Acquisition Wire Transfer',
    category: 'BEC',
    expectedClassification: 'Critical',
    expectedMinRisk: 88,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-relay.public-webmail.com ([209.85.220.41]) by mx.targetcorp.com with ESMTP id ceo_004; Thu, 03 Sep 2026 11:00:00 +0000
From: "David Henderson, Chief Executive Officer" <ceo.henderson.corp@gmail.com>
To: finance@targetcorp.com
Reply-To: david.henderson.personal@proton.me
Subject: STRICTLY CONFIDENTIAL: Wire Transfer Authorization ($185,000)
Date: Thu, 03 Sep 2026 11:00:00 +0000
Message-ID: <ceo-bec-004@public-webmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi Finance Team,

I am in an all-day executive board meeting regarding a confidential acquisition. Do not call me as I cannot take calls.
We need to initiate an urgent electronic funds wire transfer of $185,000 to the escrow account before 2:00 PM cutoff today.
Keep this strictly confidential between us—do not mention or discuss this with anyone on the floor.
Waive the normal secondary paperwork for now; I will sign the official approval forms once I return to headquarters.

Please reply immediately so I can provide the beneficiary banking and routing numbers.

David Henderson
Chief Executive Officer, TargetCorp
Sent from my iPad`,
  },

  // ========================================================
  // E. INVOICE FRAUD
  // ========================================================
  {
    id: 'E',
    name: 'Invoice Fraud - Overdue Vendor Payment',
    category: 'Invoice Fraud',
    expectedClassification: 'Critical',
    expectedMinRisk: 85,
    expectedMaxRisk: 100,
    rawEmail: `Received: from vps-992.hostinger-nodes.com ([185.220.101.5]) by mx.targetcorp.com with ESMTP id inv_005; Thu, 03 Sep 2026 11:30:00 +0000
From: "Acme Cloud Solutions Billing" <billing@acme-cloud-billing.com>
To: accounts.payable@targetcorp.com
Reply-To: settlements@acme-remittance-desk.net
Subject: OVERDUE NOTICE: Invoice #INV-88219 Final Settlement Demand
Date: Thu, 03 Sep 2026 11:30:00 +0000
Message-ID: <inv-fraud-005@acme-cloud-billing.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Accounts Payable,

Our records indicate that Invoice #INV-88219 for $48,500.00 remains unpaid.
Failure to settle this balance today will result in immediate suspension of your cloud infrastructure.

Please note our updated banking details for all wire payments:
Bank: Global Commercial Escrow
Routing Number: 021000021
Account Number: 88291048291
Beneficiary: Apex Settlement Holdings

Remit the wire payment confirmation receipt immediately to this email.`,
  },

  // ========================================================
  // F. BANK-ACCOUNT-CHANGE FRAUD
  // ========================================================
  {
    id: 'F',
    name: 'Bank Account Change Fraud - Vendor Remittance Update',
    category: 'BEC',
    expectedClassification: 'Critical',
    expectedMinRisk: 88,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail.vendor-lookalike.org ([194.26.29.11]) by mx.targetcorp.com with ESMTP id bank_006; Thu, 03 Sep 2026 11:45:00 +0000
From: "Apex Logistics Accounting" <accounting@apex-1ogistics.com>
To: ap@targetcorp.com
Subject: Urgent: Updated Banking Details for Future Wire Remittances
Date: Thu, 03 Sep 2026 11:45:00 +0000
Message-ID: <bank-chg-006@apex-1ogistics.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hello Accounting Team,

Please be advised that due to our annual audit and banking consolidation, we have changed our primary bank account.
Effective immediately, please switch all pending invoice disbursements and future wire transfers to our new account:

New Bank: First Horizon National
New Routing: 064000017
New Account: 9940281729
Beneficiary: Apex Logistics LLC

Please confirm receipt and verify that our vendor file has been updated before executing our next scheduled disbursement.`,
  },

  // ========================================================
  // G. MALWARE ATTACHMENT
  // ========================================================
  {
    id: 'G',
    name: 'Malware Attachment - Double Extension Payload',
    category: 'Malware',
    expectedClassification: 'Critical',
    expectedMinRisk: 90,
    expectedMaxRisk: 100,
    rawEmail: `Received: from smtp.external-infected.net ([185.220.100.240]) by mx.targetcorp.com with ESMTP id mal_007; Thu, 03 Sep 2026 12:00:00 +0000
From: "DHL Express Delivery Notification" <tracking-update@dhl-parcel-delivery.info>
To: target.user@targetcorp.com
Subject: Undeliverable Package Notice: Download Your Delivery Slip
Date: Thu, 03 Sep 2026 12:00:00 +0000
Message-ID: <malware-007@dhl-parcel-delivery.info>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_MALWARE_007"

------=_Part_MALWARE_007
Content-Type: text/plain; charset="UTF-8"

Dear Customer,

Your parcel DHL-992140 could not be delivered due to an incorrect destination address.
Please extract the attached delivery slip and verify your information immediately to arrange redelivery.

DHL Express Customer Service
------=_Part_MALWARE_007
Content-Type: application/x-dosexec; name="DHL_Delivery_Slip.pdf.exe"
Content-Disposition: attachment; filename="DHL_Delivery_Slip.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA=
------=_Part_MALWARE_007--`,
  },

  // ========================================================
  // H. FAKE IT NOTIFICATION
  // ========================================================
  {
    id: 'H',
    name: 'Fake IT Notification - Mailbox Storage Exceeded',
    category: 'Credential Phishing',
    expectedClassification: 'Critical',
    expectedMinRisk: 80,
    expectedMaxRisk: 98,
    rawEmail: `Received: from relay-node.spammer-vps.org ([179.43.155.10]) by mx.targetcorp.com with ESMTP id it_008; Thu, 03 Sep 2026 12:15:00 +0000
From: "IT Helpdesk & Messaging Administrator" <admin@targetcorp-support-desk.top>
To: target.user@targetcorp.com
Subject: Action Required: Your Mailbox Quota has Exceeded 98%
Date: Thu, 03 Sep 2026 12:15:00 +0000
Message-ID: <it-helpdesk-008@targetcorp-support-desk.top>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<h3>TargetCorp IT Administrator Alert</h3>
<p>Your mailbox storage has reached 49.2 GB of your 50.0 GB quota. Incoming emails will be rejected after 4:00 PM.</p>
<p>Please click below to upgrade your corporate storage allocation and retain incoming messages:</p>
<p><a href="http://targetcorp-support-desk.top/portal/auth/storage-upgrade.php">Upgrade Storage and Re-authenticate Single Sign-On</a></p>
<p>IT Messaging Infrastructure Team</p>
</body></html>`,
  },

  // ========================================================
  // I. BRAND IMPERSONATION
  // ========================================================
  {
    id: 'I',
    name: 'Brand Impersonation - PayPal Security Warning',
    category: 'Brand Impersonation',
    expectedClassification: 'Critical',
    expectedMinRisk: 85,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail.spoof-relay.cc ([194.87.139.50]) by mx.targetcorp.com with ESMTP id brand_009; Thu, 03 Sep 2026 12:30:00 +0000
From: "PayPal Resolution Center" <service-notice@paypa1-security.com>
To: target.user@targetcorp.com
Subject: Security Alert: Unauthorized Transaction of $1,250.00 Detected
Date: Thu, 03 Sep 2026 12:30:00 +0000
Message-ID: <paypal-brand-009@paypa1-security.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<h2>PayPal Security Alert</h2>
<p>We noticed an unrecognized payment of $1,250.00 to CryptoExchange Corp from an unrecognized device in Vladivostok, Russia.</p>
<p>If you did not authorize this payment, please dispute it immediately to lock your account and refund your funds:</p>
<p><a href="https://paypa1-security.com/signin/dispute-charge">Cancel Payment and Verify Identity</a></p>
</body></html>`,
  },

  // ========================================================
  // J. REPLY-TO SPOOFING
  // ========================================================
  {
    id: 'J',
    name: 'Reply-To Spoofing - Envelope Diversion',
    category: 'Reply-To Spoofing',
    expectedClassification: 'Critical',
    expectedMinRisk: 75,
    expectedMaxRisk: 95,
    rawEmail: `Received: from mail-out.relay-drop.org ([193.106.191.12]) by mx.targetcorp.com with ESMTP id reply_010; Thu, 03 Sep 2026 12:45:00 +0000
From: "Sarah Jenkins (HR Director)" <sjenkins@targetcorp.com>
Reply-To: sarah.jenkins.hr.portal@gmail.com
Return-Path: <bounce@attacker-controlled-vps.com>
To: target.user@targetcorp.com
Subject: Confidential Employee Compensation Adjustment Form
Date: Thu, 03 Sep 2026 12:45:00 +0000
Message-ID: <reply-spoof-010@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi,

Please review your revised salary compensation bracket for FY2027.
Reply directly to this email with your updated employee ID and current banking details to confirm enrollment.

Best regards,
Sarah Jenkins
Director of Human Resources`,
  },

  // ========================================================
  // K. PAYROLL PHISHING
  // ========================================================
  {
    id: 'K',
    name: 'Payroll Phishing - Direct Deposit Switch via Webmail',
    category: 'BEC',
    expectedClassification: 'Critical',
    expectedMinRisk: 70,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-relay.webmail.com ([209.85.220.41]) by mx.targetcorp.com with ESMTP id pay_011; Thu, 03 Sep 2026 13:00:00 +0000
From: "Michael Chang (Engineering)" <mchang.targetcorp@gmail.com>
To: payroll@targetcorp.com
Subject: Urgent: Change my direct deposit account before Friday payroll
Date: Thu, 03 Sep 2026 13:00:00 +0000
Message-ID: <payroll-phish-011@webmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi Payroll Team,

I recently had to switch banks due to fraud on my checking account.
Can you please update my direct deposit information for this week's paycheck?
My new routing number is 071000288 and account number is 8840192841.
Please confirm when this is completed so my salary isn't delayed.

Thanks,
Michael Chang
Senior Software Engineer`,
  },

  // ========================================================
  // L. DATA-EXFILTRATION REQUEST
  // ========================================================
  {
    id: 'L',
    name: 'Data-Exfiltration Request - Confidential Salary Table Solicitation',
    category: 'BEC',
    expectedClassification: 'High Risk',
    expectedMinRisk: 65,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-out.freemail-sender.net ([91.240.118.88]) by mx.targetcorp.com with ESMTP id exfil_012; Thu, 03 Sep 2026 13:15:00 +0000
From: "Robert Vance, Board Member" <robert.vance.targetcorp@outlook.com>
To: hr.analytics@targetcorp.com
Subject: URGENT & CONFIDENTIAL: FY2026 Complete Executive Compensation & W-2 Data
Date: Thu, 03 Sep 2026 13:15:00 +0000
Message-ID: <data-exfil-012@freemail-sender.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

HR Analytics,

I am currently assembling the board compensation committee deck for tomorrow's closed session.
Please send over an unmasked spreadsheet containing full name, SSN, current salary, and FY2026 bonus amounts for all director-level and above personnel.
Keep this strictly confidential between us as the figures have not been released to the executive team.
Send the spreadsheet directly as an attachment to this email ASAP.

Robert Vance
Board of Directors, Audit Committee`,
  },

  // ========================================================
  // M. LEGITIMATE INTERNAL EMAIL
  // ========================================================
  {
    id: 'M',
    name: 'Legitimate Internal Email - Engineering Standup Notes',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 20,
    rawEmail: `Received: from mail.targetcorp.com ([192.0.2.10]) by mx.targetcorp.com with ESMTP id legit_013; Thu, 03 Sep 2026 13:30:00 +0000
From: "Jessica Wu" <jessica.wu@targetcorp.com>
To: engineering-team@targetcorp.com
Subject: Sprint 42 Standup Notes & Architecture Review
Date: Thu, 03 Sep 2026 13:30:00 +0000
Message-ID: <standup-notes-013@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

Hi team,

Here is the quick recap from this morning's sprint planning:
- Backend refactoring for the telemetry ingestion pipeline is 80% complete.
- Front-end integration tests are scheduled for tomorrow afternoon.
- Architecture review for the Kubernetes migration will take place Thursday at 2 PM in Room 4B.

Please update your Jira tickets before EOD.

Best,
Jessica Wu
Staff Engineer, Platform Team
TargetCorp`,
  },

  // ========================================================
  // N. LEGITIMATE INVOICE
  // ========================================================
  {
    id: 'N',
    name: 'Legitimate Invoice - Standard Monthly Cloud Hosting',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 20,
    rawEmail: `Received: from mail-delivery.datadoghq.com ([199.16.156.20]) by mx.targetcorp.com with ESMTP id legit_014; Thu, 03 Sep 2026 13:45:00 +0000
From: "Datadog Billing" <billing@datadoghq.com>
To: accounts.payable@targetcorp.com
Subject: Your Datadog Monthly Statement - August 2026
Date: Thu, 03 Sep 2026 13:45:00 +0000
Message-ID: <datadog-stmt-014@datadoghq.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

<html><body>
<h3>Datadog Billing Statement</h3>
<p>Dear Customer,</p>
<p>Your monthly statement for August 2026 is now available. Your registered corporate card on file has been charged $1,420.00.</p>
<p>You can view and download your full itemized statement in the official Datadog account portal at <a href="https://app.datadoghq.com/billing">https://app.datadoghq.com/billing</a>.</p>
<p>Thank you for using Datadog!</p>
</body></html>`,
  },

  // ========================================================
  // O. LEGITIMATE HR EMAIL
  // ========================================================
  {
    id: 'O',
    name: 'Legitimate HR Email - Annual Open Enrollment Notice',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 20,
    rawEmail: `Received: from mail.targetcorp.com ([192.0.2.10]) by mx.targetcorp.com with ESMTP id legit_015; Thu, 03 Sep 2026 14:00:00 +0000
From: "TargetCorp Human Resources" <hr-benefits@targetcorp.com>
To: all-employees@targetcorp.com
Subject: Annual Healthcare & Benefits Open Enrollment (Oct 1 - Oct 31)
Date: Thu, 03 Sep 2026 14:00:00 +0000
Message-ID: <hr-benefits-015@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

Dear Colleagues,

The annual benefits open enrollment period will begin next month on October 1st and conclude on October 31st.
During this window, you may adjust your medical, dental, vision, and 401(k) allocations for the 2027 calendar year.

Information sessions will be held virtually every Wednesday at noon throughout October.
You can review the 2027 plan comparison guide on our internal intranet at https://intranet.targetcorp.com/hr/benefits-2027.

Best regards,
TargetCorp Total Rewards Team`,
  },

  // ========================================================
  // P. LEGITIMATE NEWSLETTER
  // ========================================================
  {
    id: 'P',
    name: 'Legitimate Newsletter - Weekly Tech Digest',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 20,
    rawEmail: `Received: from mail-delivery.substack.com ([168.245.10.50]) by mx.targetcorp.com with ESMTP id legit_016; Thu, 03 Sep 2026 14:15:00 +0000
From: "Cloud Architecture Weekly" <newsletter@cloudweekly.substack.com>
To: target.user@targetcorp.com
Subject: Cloud Architecture Weekly #412: Multi-Region Active-Active Patterns
Date: Thu, 03 Sep 2026 14:15:00 +0000
Message-ID: <substack-newsletter-016@cloudweekly.substack.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

<html><body>
<h2>Cloud Architecture Weekly #412</h2>
<p>Welcome to this week's issue! Highlights include:</p>
<ul>
  <li>Designing zero-downtime database failovers across multiple cloud regions</li>
  <li>Optimizing gRPC connection pooling in Go microservices</li>
</ul>
<p>Read the full issue online at <a href="https://cloudweekly.substack.com/p/issue-412">https://cloudweekly.substack.com/p/issue-412</a></p>
<p><small>You received this because you subscribed to Cloud Architecture Weekly. <a href="https://cloudweekly.substack.com/unsubscribe">Unsubscribe</a></small></p>
</body></html>`,
  },

  // ========================================================
  // Q. LEGITIMATE PASSWORD REMINDER
  // ========================================================
  {
    id: 'Q',
    name: 'Legitimate Password Reminder - 30-Day Policy Expiry Notice',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 20,
    rawEmail: `Received: from mail.targetcorp.com ([192.0.2.10]) by mx.targetcorp.com with ESMTP id legit_017; Thu, 03 Sep 2026 14:30:00 +0000
From: "TargetCorp Identity Services" <identity-notification@targetcorp.com>
To: target.user@targetcorp.com
Subject: Notification: Your corporate domain password will expire in 30 days
Date: Thu, 03 Sep 2026 14:30:00 +0000
Message-ID: <password-reminder-017@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

Hello target.user,

This is a routine reminder that your TargetCorp Active Directory password is scheduled to expire in 30 days.

No immediate action is required if you have recently changed your credentials.

To change your password at your convenience before the expiration date:
1. Press Ctrl+Alt+Delete on your corporate workstation and select "Change a password", or
2. Visit the official self-service portal at https://identity.targetcorp.com/selfservice

Please note: TargetCorp IT will NEVER ask for your current password via email or telephone.

TargetCorp Information Security Operations`,
  },

  // ========================================================
  // R. MFA PHISHING
  // ========================================================
  {
    id: 'R',
    name: 'MFA Phishing - Microsoft Authenticator OTP Harvest',
    category: 'MFA Phishing',
    expectedClassification: 'Critical',
    expectedMinRisk: 80,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-relay.hostile-mfa.net ([198.51.100.99]) by mx.targetcorp.com with ESMTP id mfa_018; Thu, 03 Sep 2026 14:45:00 +0000
From: "Microsoft Identity Verification" <security-mfa@mfa-auth-portal.com>
To: target.user@targetcorp.com
Subject: Action Required: Confirm Your Microsoft 2FA Security Code
Date: Thu, 03 Sep 2026 14:45:00 +0000
Message-ID: <mfa-harvest-018@mfa-auth-portal.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<h2>Microsoft Authenticator Verification</h2>
<p>A new sign-in attempt was detected on your account from Windows 11 in Frankfurt, Germany.</p>
<p>To confirm your identity, enter your 6-digit Multi-Factor Authentication (MFA) code and password at the verification link:</p>
<p><a href="https://mfa-auth-portal.com/login/mfa-verify.php">Verify MFA Token Now</a></p>
<p>If you did not initiate this request, your session will be locked immediately.</p>
</body></html>`,
  },

  // ========================================================
  // S. TYPOSQUATTED / LOOKALIKE DOMAIN
  // ========================================================
  {
    id: 'S',
    name: 'Lookalike Typosquatting - Microsoft OneDrive Phish',
    category: 'Brand Impersonation',
    expectedClassification: 'Critical',
    expectedMinRisk: 80,
    expectedMaxRisk: 100,
    rawEmail: `Received: from vps-node.clone-host.org ([194.26.29.90]) by mx.targetcorp.com with ESMTP id typo_019; Thu, 03 Sep 2026 15:00:00 +0000
From: "Microsoft SharePoint Notifications" <sharing@micros0ft-sharepoint.com>
To: target.user@targetcorp.com
Subject: Document Shared: Q4 Financial Targets & Executive Deck
Date: Thu, 03 Sep 2026 15:00:00 +0000
Message-ID: <typo-share-019@micros0ft-sharepoint.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<p>A confidential presentation has been shared via Microsoft SharePoint.</p>
<p><a href="https://micros0ft-sharepoint.com/auth/login">Click to view Q4_Targets.pptx</a></p>
</body></html>`,
  },

  // ========================================================
  // T. AMBIGUOUS ROUTINE BUSINESS EMAIL
  // ========================================================
  {
    id: 'T',
    name: 'Ambiguous Routine Business Email - Meeting Reschedule',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 25,
    rawEmail: `Received: from mail.targetcorp.com ([192.0.2.10]) by mx.targetcorp.com with ESMTP id legit_020; Thu, 03 Sep 2026 15:15:00 +0000
From: "Marcus Vance" <marcus.vance@targetcorp.com>
To: target.user@targetcorp.com
Subject: Rescheduling our sync to tomorrow morning
Date: Thu, 03 Sep 2026 15:15:00 +0000
Message-ID: <reschedule-020@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

Hi,

Something came up for our 3:00 PM 1-on-1 today. Could we push our catch-up to tomorrow morning around 10:30 AM?
Let me know if that time works on your calendar.

Thanks,
Marcus`,
  },

  // ========================================================
  // U. MFA NUMBER MATCHING / AITM PHISHING
  // ========================================================
  {
    id: 'U',
    name: 'MFA Phishing - Number Matching & Session Replay Lure',
    category: 'MFA Phishing',
    expectedClassification: 'Critical',
    expectedMinRisk: 80,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-node.mfa-proxy-relay.org ([185.220.101.5]) by mx.targetcorp.com with ESMTP id mfa_021; Thu, 03 Sep 2026 15:30:00 +0000
From: "Okta Identity Verification" <alerts@auth-session-sync.biz>
To: target.user@targetcorp.com
Subject: Action Required: Number Match Authentication Request (Code: 84)
Date: Thu, 03 Sep 2026 15:30:00 +0000
Message-ID: <okta-match-021@auth-session-sync.biz>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=fail; dkim=fail; dmarc=fail

<html><body>
<h2>Okta Multi-Factor Authentication Alert</h2>
<p>A sign-in request for your single sign-on corporate account requires secondary device approval.</p>
<p>Verification Code: <strong style="font-size: 24px; color: #d9534f;">84</strong></p>
<p>If you are currently signing in, tap <strong>84</strong> on your authenticator mobile app or confirm your identity at our session synchronization portal:</p>
<p><a href="https://auth-session-sync.biz/sso/verify-token.php">Synchronize Identity & Approve MFA Session</a></p>
<p><small>If you did not initiate this request, unauthorized access may be attempted. Confirm your credentials immediately to revoke pending sessions.</small></p>
</body></html>`,
  },

  // ========================================================
  // V. EXECUTIVE BEC - GIFT CARD PURCHASE
  // ========================================================
  {
    id: 'V',
    name: 'Executive BEC - Discretionary Gift Card Purchase',
    category: 'BEC',
    expectedClassification: 'Critical',
    expectedMinRisk: 80,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail-relay.freemail-server.net ([198.51.100.201]) by mx.targetcorp.com with ESMTP id bec_022; Thu, 03 Sep 2026 15:45:00 +0000
From: "David Sterling (CEO)" <david.sterling.targetcorp@gmail.com>
To: target.user@targetcorp.com
Reply-To: exec.office.confidential@mailinator.com
Subject: Quick discretionary request - In a board meeting
Date: Thu, 03 Sep 2026 15:45:00 +0000
Message-ID: <giftcard-022@freemail-server.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi,

I'm tied up in confidential board reviews for the next few hours and cannot take calls.
I need you to handle an urgent confidential task for me right away. We are presenting surprise recognition incentives to select project partners this evening.

Please purchase 5 Apple Gift Cards at $200 each ($1,000 total) from a nearby store.
Scratch the back, take clear photos of the redemption codes, and email them directly back to this thread.

Keep this strictly between us until the official announcement. I will ensure Finance reimburses you before end of day.

Thanks,
David Sterling
Chief Executive Officer`,
  },

  // ========================================================
  // W. INVOICE FRAUD - THREAD HIJACKING
  // ========================================================
  {
    id: 'W',
    name: 'Invoice Fraud - Compromised Thread Hijack',
    category: 'Invoice Fraud',
    expectedClassification: 'Critical',
    expectedMinRisk: 85,
    expectedMaxRisk: 100,
    rawEmail: `Received: from relay01.typo-vendor.com ([185.190.140.77]) by mx.targetcorp.com with ESMTP id inv_023; Thu, 03 Sep 2026 16:00:00 +0000
From: "Apex Billing Department" <billing@apex-technol0gies.com>
To: target.user@targetcorp.com
Subject: Re: Outstanding Invoice #INV-88219 - Payment Processing
Date: Thu, 03 Sep 2026 16:00:00 +0000
Message-ID: <thread-hijack-023@apex-technol0gies.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi TargetCorp Accounts Payable,

Following up on the invoice #INV-88219 discussed below for $48,500.00.

Please note that our primary merchant depository institution has changed due to an annual financial audit.
Do NOT remit payment to the previous bank account on file.

Please update our vendor payment details to our new settlement account:
Bank Name: First Global Commercial Bank
Account Name: Apex Technologies Settlement LLC
Routing Transit Number: 021000089
Account Number: 8839-2019-4412
Swift/BIC: FGCBUS33

Please confirm once the electronic wire transfer is initiated so we can issue your receipt without service disruption.

Best regards,
Apex Technologies Billing Operations`,
  },

  // ========================================================
  // X. MALICIOUS SCRIPT ATTACHMENT (.VBS)
  // ========================================================
  {
    id: 'X',
    name: 'Malicious Script Payload - Voicemail Audio Dropper (.vbs)',
    category: 'Malware Delivery',
    expectedClassification: 'Critical',
    expectedMinRisk: 85,
    expectedMaxRisk: 100,
    rawEmail: `Received: from mail.telecom-relay.org ([194.67.210.88]) by mx.targetcorp.com with ESMTP id mal_024; Thu, 03 Sep 2026 16:15:00 +0000
From: "Corporate Voicemail System" <pbx-notification@telecom-cloud.net>
To: target.user@targetcorp.com
Subject: New Voicemail Received (38 seconds) - Caller ID: +1 (202) 555-0143
Date: Thu, 03 Sep 2026 16:15:00 +0000
Message-ID: <voicemail-024@telecom-cloud.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_VOICEMAIL_88192"

------=_Part_VOICEMAIL_88192
Content-Type: text/html; charset="UTF-8"

<html><body>
<h3>You have received a new voice message.</h3>
<p><strong>Duration:</strong> 00:38</p>
<p><strong>Caller:</strong> +1 (202) 555-0143</p>
<p><strong>Date:</strong> Sep 03, 2026 16:14 UTC</p>
<p>The audio recording and transcription are attached for your review.</p>
</body></html>

------=_Part_VOICEMAIL_88192
Content-Type: application/x-vbs; name="Voicemail_Audio_Recording_38s.vbs"
Content-Disposition: attachment; filename="Voicemail_Audio_Recording_38s.vbs"
Content-Transfer-Encoding: base64

J21hbGljaW91cyBzY3JpcHQgcGF5bG9hZCBzbmlwcGV0
------=_Part_VOICEMAIL_88192--`,
  },

  // ========================================================
  // Y. QUISHING / QR CODE CREDENTIAL LURE
  // ========================================================
  {
    id: 'Y',
    name: 'Quishing - QR Code Credential Lure',
    category: 'Credential Phishing',
    expectedClassification: 'High Risk',
    expectedMinRisk: 70,
    expectedMaxRisk: 95,
    rawEmail: `Received: from relay02.auth-scanner.biz ([91.240.118.99]) by mx.targetcorp.com with ESMTP id qsh_025; Thu, 03 Sep 2026 16:30:00 +0000
From: "Microsoft 365 Security Operations" <it-admin@m365-authenticator-setup.com>
To: target.user@targetcorp.com
Subject: Mandatory Security Upgrade: Scan QR Code to Keep Authenticator Active
Date: Thu, 03 Sep 2026 16:30:00 +0000
Message-ID: <quishing-025@m365-authenticator-setup.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<h2>Microsoft Authentication Architecture Update</h2>
<p>TargetCorp is rolling out mandatory FIDO2 multi-factor protection.</p>
<p>Due to upcoming security policy enforcement, your mobile device authenticator token must be re-registered within 48 hours.</p>
<p>Please open your mobile camera and scan the secure enrollment QR code below, or visit <a href="https://login-m365-qr.net/auth">https://login-m365-qr.net/auth</a> to complete your identity verification:</p>
<div style="border: 2px dashed #0B1F3A; padding: 20px; display: inline-block;">
  [EMBEDDED SECURE ENROLLMENT QR CODE: https://login-m365-qr.net/auth]
</div>
<p>Failure to register before the maintenance deadline will lock your enterprise account.</p>
</body></html>`,
  },

  // ========================================================
  // Z. CALLBACK PHISHING (REVERSE VISHING)
  // ========================================================
  {
    id: 'Z',
    name: 'Callback Phishing - Fake Technical Support / Geek Squad Invoice',
    category: 'Social Engineering',
    expectedClassification: 'High Risk',
    expectedMinRisk: 70,
    expectedMaxRisk: 95,
    rawEmail: `Received: from mail-relay.consumer-bill.org ([198.51.100.155]) by mx.targetcorp.com with ESMTP id cb_026; Thu, 03 Sep 2026 16:45:00 +0000
From: "Geek Squad Protection Service" <subscriptions@geek-billing-care.com>
To: target.user@targetcorp.com
Subject: Invoice Confirmation: Order #GS-99182-X for $499.99 auto-debited
Date: Thu, 03 Sep 2026 16:45:00 +0000
Message-ID: <callback-026@geek-billing-care.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<h2>Geek Squad Annual Service Renewal</h2>
<p>Dear Customer,</p>
<p>Thank you for your ongoing subscription to Geek Squad Total Protection Plan.</p>
<p>Your subscription has successfully renewed today. An amount of <strong>$499.99</strong> has been debited from your checking account / card on file.</p>
<p><strong>Item Description:</strong> 3-Year Extended Antivirus, Firewall & Telephony Care</p>
<p><strong>Order Number:</strong> GS-99182-X</p>
<p>If you did not authorize this charge or wish to cancel your subscription and request an immediate refund, you must contact our dispute department within 24 hours at:</p>
<p><strong style="font-size: 20px; color: #c9302c;">Toll-Free Support Line: +1 (800) 555-0199</strong></p>
<p>Our representative will guide you through the refund verification process over the phone.</p>
</body></html>`,
  },

  // ========================================================
  // AA. BORDERLINE / AMBIGUOUS VENDOR DISPUTE
  // ========================================================
  {
    id: 'AA',
    name: 'Borderline Vendor Dispute - Overdue Balance Inquiry',
    category: 'Suspicious',
    expectedClassification: 'Suspicious',
    expectedMinRisk: 35,
    expectedMaxRisk: 60,
    rawEmail: `Received: from mail.premier-consulting.com ([198.51.100.82]) by mx.targetcorp.com with ESMTP id dispute_027; Thu, 03 Sep 2026 17:00:00 +0000
From: "Arthur Pendelton" <apendelton@premier-consulting.com>
To: target.user@targetcorp.com
Subject: URGENT: Delinquent account notice - Project Titan retainers
Date: Thu, 03 Sep 2026 17:00:00 +0000
Message-ID: <dispute-027@premier-consulting.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=none

TargetCorp Accounts Payable Team,

I am writing with grave concern regarding our outstanding statement for July and August consulting deliverables ($14,250.00), which is now 45 days overdue.

We have attempted to reach your finance contact multiple times without response. If payment confirmation is not received by end of business Friday, we will be forced to pause our ongoing API migration support and refer the balance to corporate collections.

Please review your records and reply with the payment transaction reference immediately.

Arthur Pendelton
Managing Partner, Premier Strategic Consulting
Direct: +1 (312) 555-0142`,
  },

  // ========================================================
  // BB. BORDERLINE INTERNAL URGENT REVIEW
  // ========================================================
  {
    id: 'BB',
    name: 'Borderline Internal Urgency - Urgent Confidential Executive Draft',
    category: 'Low Risk',
    expectedClassification: 'Low Risk',
    expectedMinRisk: 15,
    expectedMaxRisk: 40,
    rawEmail: `Received: from mail.targetcorp.com ([192.0.2.10]) by mx.targetcorp.com with ESMTP id border_028; Thu, 03 Sep 2026 17:15:00 +0000
From: "Elena Rostova" <elena.rostova@targetcorp.com>
To: target.user@targetcorp.com
Subject: Highly Confidential: Embargoed leadership transition announcement draft
Date: Thu, 03 Sep 2026 17:15:00 +0000
Message-ID: <internal-confidential-028@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

Hi,

Please review the attached notes regarding the leadership transition announcement scheduled for tomorrow morning.
Do not forward or share this with anyone outside the core comms team prior to the official 9:00 AM press release.

Let me know by 6:00 PM if there are any factual corrections needed on the quote attribution.

Thanks,
Elena Rostova
VP Corporate Communications | TargetCorp`,
  },

  // ========================================================
  // CC. LEGITIMATE HR BENEFITS ENROLLMENT
  // ========================================================
  {
    id: 'CC',
    name: 'Legitimate HR Benefits Open Enrollment with External Portal',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 25,
    rawEmail: `Received: from mail.targetcorp.com ([192.0.2.10]) by mx.targetcorp.com with ESMTP id legit_029; Thu, 03 Sep 2026 17:30:00 +0000
From: "TargetCorp Human Resources" <hr-benefits@targetcorp.com>
To: target.user@targetcorp.com
Subject: Action Optional: 2027 Healthcare & Benefits Open Enrollment is Now Live
Date: Thu, 03 Sep 2026 17:30:00 +0000
Message-ID: <hr-benefits-029@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

<html><body>
<h2>TargetCorp Annual Benefits Open Enrollment</h2>
<p>Dear TargetCorp Colleague,</p>
<p>Our annual open enrollment window for 2027 healthcare, dental, and 401(k) retirement plans is open from October 1 through October 25.</p>
<p>If you wish to keep your existing benefit elections, no action is required—your current coverage will automatically roll over.</p>
<p>To view your coverage options, review plan comparison charts, or modify elections, please access our secure third-party benefits portal:</p>
<p><a href="https://mybenefits.adp.com/targetcorp">https://mybenefits.adp.com/targetcorp</a></p>
<p>Questions may be directed to our internal benefits helpdesk at benefits-support@targetcorp.com.</p>
<p>Warm regards,<br>TargetCorp People & Culture Team</p>
</body></html>`,
  },

  // ========================================================
  // DD. LEGITIMATE IT INFRASTRUCTURE NOTIFICATION
  // ========================================================
  {
    id: 'DD',
    name: 'Legitimate IT Infrastructure Notice - Scheduled Network Maintenance',
    category: 'Clean',
    expectedClassification: 'Clean',
    expectedMinRisk: 0,
    expectedMaxRisk: 20,
    rawEmail: `Received: from mail.targetcorp.com ([192.0.2.10]) by mx.targetcorp.com with ESMTP id legit_030; Thu, 03 Sep 2026 17:45:00 +0000
From: "TargetCorp Network Operations" <noc-alerts@targetcorp.com>
To: target.user@targetcorp.com
Subject: Scheduled Maintenance Window: Data Center Core Switch Upgrade (Sunday 02:00-04:00 UTC)
Date: Thu, 03 Sep 2026 17:45:00 +0000
Message-ID: <noc-alert-030@targetcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.targetcorp.com; spf=pass; dkim=pass; dmarc=pass

Hello all,

The TargetCorp Infrastructure Engineering team will perform scheduled firmware upgrades on our primary core network switches this Sunday, September 6, between 02:00 and 04:00 UTC.

Impact:
- Brief intermittent connectivity drops (under 3 minutes) may affect internal corporate VPN access during switch failover.
- Cloud services (Microsoft 365, Slack, Jira) will remain accessible without interruption.

Note: TargetCorp IT will never ask for your password or credentials during maintenance windows. No user action is required.

For real-time infrastructure status, please check our internal status dashboard:
https://status.internal.targetcorp.com

TargetCorp Network Operations Center (NOC)`,
  },
];
