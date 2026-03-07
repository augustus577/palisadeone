# PALISADE ONE — Phishing Simulation Templates (100)
# For security awareness training — test client employees
# Deploy via: n8n workflow, GoPhish (open source), or KnowBe4
#
# DIFFICULTY LEVELS:
#   EASY   = obvious red flags, most people should catch these
#   MEDIUM = realistic, requires attention to spot
#   HARD   = very convincing, mimics real attacks closely
#
# Each template includes: Subject, From Name, From Email pattern, Body, Red Flags
# Replace [COMPANY] with the client's actual company name
# Replace [DOMAIN] with a lookalike domain (e.g., micr0soft.com, paypa1.com)

---

# ========================================
# CATEGORY 1: MICROSOFT / O365 (1-15)
# ========================================

## Phish 1 — M365 Password Expiry (EASY)
**Subject**: Your password expires in 24 hours
**From**: Microsoft 365 Team <no-reply@microsft-security.com>
```
Your Microsoft 365 password will expire in 24 hours.

To avoid losing access to your email and files, please update your password immediately.

[UPDATE PASSWORD NOW]

If you did not request this change, please disregard this email.

Microsoft 365 Security Team
```
**Red Flags**: Misspelled domain (microsft), urgency, generic greeting, suspicious link

## Phish 2 — Shared Document (MEDIUM)
**Subject**: [Coworker Name] shared a document with you
**From**: Microsoft SharePoint <sharepoint@microsoft-notifications.com>
```
[Coworker Name] shared a file with you

"Q4 Budget Review - FINAL.xlsx"

This document requires you to sign in to view.

[OPEN DOCUMENT]

Microsoft SharePoint Online
You're receiving this because [Coworker Name] shared a file from [COMPANY]'s SharePoint.
```
**Red Flags**: External domain (not microsoft.com), requires sign-in to view, uses real coworker name

## Phish 3 — MFA Reset (HARD)
**Subject**: Action Required: Verify your identity
**From**: Microsoft Security <security-noreply@microsoft.com.alerts-center.com>
```
We detected an unusual sign-in to your Microsoft 365 account.

Location: Moscow, Russia
Device: Unknown Linux Device
Time: [current date/time]

If this wasn't you, your account may be compromised. Please verify your identity immediately to secure your account.

[VERIFY MY IDENTITY]

If this was you, you can safely ignore this email.

Microsoft Account Security
This is an automated message from Microsoft Corporation, One Microsoft Way, Redmond, WA 98052.
```
**Red Flags**: Subdomain trick (microsoft.com.alerts-center.com), fear/urgency, looks very real

## Phish 4 — Teams Missed Message (MEDIUM)
**Subject**: You have 3 unread messages in Teams
**From**: Microsoft Teams <teams@microsoft-teams-notify.com>
```
You have 3 unread messages

[Boss Name] sent you a message:
"Hey, can you review this before the meeting today? It's urgent."

[VIEW IN TEAMS]

You're receiving this because you have notifications enabled.
Microsoft Teams | Microsoft Corporation
```
**Red Flags**: Fake domain, uses boss's name (social engineering), urgency

## Phish 5 — OneDrive Storage Full (EASY)
**Subject**: Your OneDrive storage is 95% full
**From**: OneDrive <alert@onedrive-microsoft.com>
```
WARNING: Your OneDrive storage is almost full.

You have used 4.75 GB of 5 GB.

If your storage exceeds the limit, you will no longer be able to sync files.

[UPGRADE STORAGE - FREE]
[MANAGE FILES]

Microsoft OneDrive
```
**Red Flags**: Wrong domain, "free upgrade" lure, generic warning

## Phish 6 — Voicemail Notification (MEDIUM)
**Subject**: New voicemail from +1 (410) 555-XXXX
**From**: Microsoft 365 Voicemail <voicemail@outlook-services.com>
```
You received a new voicemail

Duration: 0:47
From: +1 (410) 555-XXXX
Date: [today's date]

[PLAY VOICEMAIL]

This message was sent to your Microsoft 365 mailbox.
```
**Red Flags**: Fake domain, voicemail-to-email phishing (common real attack vector)

## Phish 7 — Account Locked (EASY)
**Subject**: URGENT: Your account has been locked
**From**: Microsoft Support <support@microsoft-account-verify.com>
```
Your Microsoft account has been temporarily locked due to suspicious activity.

To unlock your account, please verify your identity:

[UNLOCK ACCOUNT]

If you don't verify within 24 hours, your account will be permanently deleted.

Microsoft Account Team
```
**Red Flags**: "Permanently deleted" threat (Microsoft never does this), urgency, fake domain

## Phish 8 — Email Quarantine (HARD)
**Subject**: [3] Messages held in quarantine
**From**: [COMPANY] IT Security <quarantine@[company-domain-typo].com>
```
Email Security Notification

3 messages addressed to you have been held in quarantine due to security policy.

Subject: Invoice #38291 — Payment Due
Subject: RE: Meeting Tomorrow
Subject: Salary Adjustment Notice - Confidential

[REVIEW QUARANTINED MESSAGES]
[RELEASE ALL]

This is an automated message from [COMPANY]'s email security system.
IT Help Desk: ext. 4100
```
**Red Flags**: Looks like internal IT, uses company name, tempting subject lines in quarantine

## Phish 9 — Teams Meeting Recording (MEDIUM)
**Subject**: Meeting recording: "All Hands Q1 Review" is ready
**From**: Microsoft Teams <notifications@teams-microsoft.online>
```
A recording of your recent meeting is ready to view.

Meeting: All Hands Q1 Review
Date: [recent date]
Duration: 1:23:47
Recorded by: [Executive Name]

[WATCH RECORDING]

This recording will expire in 30 days.
Microsoft Teams
```
**Red Flags**: .online domain, executive name for authority, expiration urgency

## Phish 10 — License Renewal (MEDIUM)
**Subject**: Your Microsoft 365 license needs renewal
**From**: Microsoft Billing <billing@microsoft365-renewal.com>
```
Your Microsoft 365 Business license is expiring on [date + 3 days].

If not renewed, you will lose access to:
- Outlook Email
- OneDrive Files
- Teams
- SharePoint

[RENEW LICENSE - $0.00]

Current plan: Microsoft 365 Business Basic
Account: [target's email]

Microsoft Billing
```
**Red Flags**: Fake domain, $0.00 renewal (too good to be true), shows target's real email

## Phish 11-15 — More Microsoft Variations
**11 — Excel file shared** | Subject: "Annual Review Scores - Confidential.xlsx" | From: HR | Curiosity + authority bait
**12 — Outlook update required** | Subject: "Update Outlook to continue receiving emails" | From: IT Department | Fear of losing email
**13 — Encrypted message** | Subject: "You have a new encrypted message" | From: Microsoft Secure | Requires "login" to view
**14 — Calendar invite** | Subject: "New meeting: Salary Discussion" | From: HR Director | Irresistible curiosity bait
**15 — Security alert** | Subject: "Someone is trying to access your account" | From: Microsoft Security | Fear-based, location data included

---

# ========================================
# CATEGORY 2: GOOGLE / WORKSPACE (16-25)
# ========================================

## Phish 16 — Google Drive Share (MEDIUM)
**Subject**: Document shared with you: "Employee Termination List 2026.docx"
**From**: Google Drive <drive-noreply@google-docs-share.com>
```
[Executive Name] has shared a document with you.

"Employee Termination List 2026.docx"

[OPEN IN GOOGLE DOCS]

Google Drive: You have new items shared with you.
Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043
```
**Red Flags**: Irresistible subject, fake domain, executive name

## Phish 17 — Gmail Storage (EASY)
**Subject**: Gmail: Your storage is full
**From**: Google <no-reply@googl-storage.com>
```
Your Google account storage is full. You can no longer send or receive emails.

[GET 15 GB FREE]
[MANAGE STORAGE]

Google Storage Team
```
**Red Flags**: Obvious misspelling (googl), "free" bait

## Phish 18 — Google Security Alert (HARD)
**Subject**: Security alert: New sign-in from Windows
**From**: Google <no-reply@accounts.google.com.secure-check.com>
```
New sign-in to your Google Account

Someone just signed in to your account from a new device.

[Your email]
Windows device
Kyiv, Ukraine
[timestamp]

If this was you, you don't need to do anything.
If this wasn't you, we'll help you secure your account.

[CHECK ACTIVITY]   [SECURE ACCOUNT]

You can also see security activity at https://myaccount.google.com/notifications

Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043
```
**Red Flags**: Subdomain trick on legit-looking domain, very realistic formatting

## Phish 19-25 — Google Variations
**19** — Google Calendar invite: "Performance Review - Mandatory" | From: HR Manager
**20** — Google Forms: "IT Equipment Survey - Required by Friday" | Links to fake form
**21** — Gmail 2FA reset: "Your 2-step verification settings were changed" | Panic trigger
**22** — Google Workspace admin: "New policy requires password change" | Authority + urgency
**23** — Google Photos: "Someone shared an album with you" | Curiosity
**24** — YouTube: "Your video received a copyright strike" | Fear (for anyone with a channel)
**25** — Google Voice: "New voicemail transcription" | Voicemail phishing variant

---

# ========================================
# CATEGORY 3: FINANCIAL / BANKING (26-40)
# ========================================

## Phish 26 — Bank Alert: Suspicious Transaction (HARD)
**Subject**: Alert: Unusual transaction on your account
**From**: Bank of America <alerts@bankofamerica-secure.com>
```
We detected an unusual transaction on your account.

Transaction Details:
- Amount: $2,847.00
- Merchant: WIRE TRANSFER - INTERNATIONAL
- Date: [today]
- Status: Pending

If you authorized this transaction, no action is needed.
If you DID NOT authorize this, please verify your identity immediately to cancel it.

[CANCEL TRANSACTION]

Bank of America Security
To learn more about how we protect you, visit bankofamerica.com/security
Member FDIC. Equal Housing Lender.

Ref: SEC-[random numbers]
```
**Red Flags**: Fake domain, large transaction fear, urgency to "cancel"

## Phish 27 — PayPal Payment Received (MEDIUM)
**Subject**: You've received $750.00
**From**: PayPal <service@paypa1-notification.com>
```
You've received a payment!

$750.00 USD from John Mitchell

Note from sender: "Payment for consulting work - March"

[VIEW PAYMENT DETAILS]

This payment is pending your confirmation. If you don't confirm within 48 hours, the funds will be returned.

PayPal
```
**Red Flags**: l/1 swap in domain, unexpected payment, urgency

## Phish 28 — Direct Deposit Change (HARD)
**Subject**: Direct deposit update confirmation
**From**: [COMPANY] Payroll <payroll@[company-lookalike].com>
```
Hi [First Name],

Your direct deposit information has been updated.

New bank: Chase Bank (ending in 4891)
Effective: Next pay period

If you did not request this change, please click below to cancel immediately.

[CANCEL CHANGE]

[COMPANY] Payroll Department
This is an automated notification. Do not reply to this email.
```
**Red Flags**: Looks internal, panic trigger, "cancel" urgency, payroll is high-value target

## Phish 29 — Wire Transfer Request (HARD — CEO Fraud)
**Subject**: Urgent — wire transfer needed
**From**: [CEO Name] <[ceo.name]@[company-typo].com>
```
[First Name],

I need you to process a wire transfer today. It's for a vendor payment that's past due and they're threatening to cut off service.

Amount: $18,500
Bank: JPMorgan Chase
Account: [number]
Routing: [number]

Please handle this ASAP and confirm when it's done. I'm in meetings all day so just email me back.

Thanks,
[CEO Name]
```
**Red Flags**: CEO impersonation, urgency, can't call to verify (in meetings), financial request

## Phish 30 — Invoice from Vendor (MEDIUM)
**Subject**: Invoice #INV-2026-0847 — Payment Due
**From**: QuickBooks <invoice@quickbooks-billing.com>
```
Invoice from ABC Supplies LLC

Invoice #: INV-2026-0847
Amount Due: $3,241.00
Due Date: [today + 2 days]

[VIEW AND PAY INVOICE]

Powered by QuickBooks Online
Intuit Inc., 2700 Coast Avenue, Mountain View, CA 94043
```
**Red Flags**: Fake QuickBooks domain, unknown vendor, urgency

## Phish 31-35 — More Financial
**31** — Zelle payment notification: "You received $500 from [Name]" | Fake Zelle domain
**32** — Tax refund: "Your IRS refund of $3,247 is ready" | IRS never emails about refunds
**33** — Credit card locked: "Your Visa ending in 4821 has been locked" | Panic trigger
**34** — Venmo request: "[Name] requested $85.00" | Social engineering
**35** — ACH payment failed: "Your recent ACH payment was returned" | Business-relevant fear

## Phish 36-40 — Financial Follow-ups / Variations
**36** — Stripe payout failed: "Your payout of $1,247.00 could not be processed" | For businesses
**37** — W-2 request from HR: "Please confirm your W-2 information" | Tax season social engineering
**38** — Amazon Business order confirmation: "Your order of 5x MacBook Pro has shipped" | Panic at unauthorized purchase
**39** — NetSuite login: "Your NetSuite session has expired" | For companies using ERP
**40** — Benefits enrollment: "Open enrollment closes tomorrow — update your benefits" | HR authority + deadline

---

# ========================================
# CATEGORY 4: SHIPPING / DELIVERY (41-50)
# ========================================

## Phish 41 — FedEx Delivery Failed (EASY)
**Subject**: FedEx: Delivery attempt failed — action required
**From**: FedEx <tracking@fedex-delivery-notice.com>
```
We attempted to deliver your package but no one was available.

Tracking Number: 7891-2345-6780
Status: Delivery Failed — Address Issue

To reschedule delivery, please confirm your address:

[RESCHEDULE DELIVERY]

FedEx
```
**Red Flags**: Fake domain, no specific package info, generic

## Phish 42 — UPS Customs Fee (MEDIUM)
**Subject**: UPS: Customs clearance required — $11.80 fee
**From**: UPS <customs@ups-parcel-center.com>
```
Your package is held at customs and requires a small clearance fee.

Package ID: 1Z999AA10123456784
Fee: $11.80

[PAY CUSTOMS FEE]

If not paid within 48 hours, the package will be returned to sender.

UPS International
```
**Red Flags**: Small fee (makes people less suspicious), urgency, fake domain

## Phish 43 — Amazon Order Confirmation (MEDIUM)
**Subject**: Your Amazon order #112-4738291-5829473 has shipped
**From**: Amazon <ship-confirm@amazn-orders.com>
```
Your order has shipped!

Order #112-4738291-5829473
Item: Apple AirPods Pro (2nd Gen) — Qty: 3
Total: $747.00
Delivery: March 10, 2026

[TRACK PACKAGE]
[DIDN'T ORDER THIS? CANCEL NOW]

Amazon.com
```
**Red Flags**: Expensive order you didn't place, "cancel" button is the trap, misspelled domain

## Phish 44 — USPS Redelivery (EASY)
**Subject**: USPS: Your package could not be delivered
**From**: USPS <no-reply@usps-redelivery.com>
```
We were unable to deliver your package.

To schedule redelivery, click below:
[SCHEDULE REDELIVERY]

Tracking: 9400111899223847562

United States Postal Service
```
**Red Flags**: USPS never emails about deliveries, fake domain

## Phish 45-50 — More Shipping
**45** — DHL customs: "Shipment held — verify identity" | International angle
**46** — Amazon return: "Your return request has been denied" | Frustration trigger
**47** — Walmart order: "Your Walmart+ order was charged $312.00" | Didn't order it
**48** — eBay won bid: "You won: Rolex Submariner — Pay now" | Exciting + urgency
**49** — Instacart: "Your order is on its way" | Confusing if you didn't order
**50** — FedEx customs invoice: PDF attachment named "CustomsInvoice.pdf.exe" | Attachment-based

---

# ========================================
# CATEGORY 5: HR / INTERNAL (51-65)
# ========================================

## Phish 51 — Salary Increase Notification (HARD)
**Subject**: Salary Adjustment Notice — Confidential
**From**: [COMPANY] HR <hr@[company-lookalike].com>
```
Dear [First Name],

Following the annual compensation review, your salary has been adjusted effective next pay period.

To view your updated compensation details, please log in to the HR portal:

[VIEW COMPENSATION UPDATE]

This information is confidential. Please do not share or forward this email.

Human Resources
[COMPANY]
```
**Red Flags**: Irresistible curiosity, looks internal, "confidential" adds legitimacy

## Phish 52 — Mandatory Training (MEDIUM)
**Subject**: Required: Annual Compliance Training — Due Friday
**From**: [COMPANY] Training <training@[company-lookalike].com>
```
Hi [First Name],

You have not completed your annual compliance training. This is required for all employees and must be completed by [Friday date].

Failure to complete by the deadline may result in disciplinary action.

[START TRAINING NOW]

HR Training Department
[COMPANY]
```
**Red Flags**: Authority (HR), threat (disciplinary action), deadline

## Phish 53 — IT Password Reset (HARD)
**Subject**: [COMPANY] IT: Password reset required
**From**: IT Help Desk <helpdesk@[company-lookalike].com>
```
Hi [First Name],

As part of our quarterly security update, all employees are required to reset their password by end of day [tomorrow].

Please use the link below to reset your password:

[RESET PASSWORD]

If you have questions, contact the help desk at ext. 4100.

IT Department
[COMPANY]
```
**Red Flags**: Looks completely internal, uses real help desk extension, routine request

## Phish 54 — Employee Survey (MEDIUM)
**Subject**: Quick survey: How are we doing? (2 min)
**From**: [CEO Name] <[ceo]@[company-lookalike].com>
```
Hi team,

I want to hear from you. We're running a quick anonymous employee satisfaction survey.

It takes 2 minutes and your responses are 100% confidential.

[TAKE THE SURVEY]

Thanks for your honesty.

[CEO Name]
CEO, [COMPANY]
```
**Red Flags**: CEO name = authority, "anonymous" = safety feeling, seems harmless

## Phish 55 — Org Chart Update (MEDIUM)
**Subject**: Updated org chart — new structure effective Monday
**From**: [COMPANY] HR <hr@[company-lookalike].com>
```
Hi all,

Please review the updated organizational chart reflecting changes effective [Monday date].

[VIEW ORG CHART]

Key changes:
- New VP of Operations reporting to CEO
- Sales team restructure
- IT department consolidation

Please review and direct questions to your manager.

Human Resources
```
**Red Flags**: Everyone wants to see org changes (curiosity), looks routine

## Phish 56 — Bonus Announcement (HARD)
**Subject**: Q1 Bonus Payout — Action Required
**From**: [COMPANY] Payroll <payroll@[company-lookalike].com>
```
Hi [First Name],

Congratulations! Based on Q1 performance, you are eligible for a bonus payout.

Bonus Amount: $2,400.00
Payout Date: Next pay period

To receive your bonus, please confirm your direct deposit information:

[CONFIRM DEPOSIT INFO]

Payroll Department
[COMPANY]
```
**Red Flags**: Everyone wants a bonus, asks for bank info confirmation, looks internal

## Phish 57 — PTO Balance (MEDIUM)
**Subject**: Your PTO balance needs attention
**From**: [COMPANY] HR <hr-benefits@[company-lookalike].com>
```
Hi [First Name],

Our records show you have 14.5 unused PTO days. Per company policy, unused days exceeding 10 will expire on March 31.

Please log in to review and schedule time off:

[VIEW PTO BALANCE]

HR Benefits
[COMPANY]
```
**Red Flags**: "Use it or lose it" urgency, looks routine, personally relevant

## Phish 58 — New Employee Directory (EASY)
**Subject**: Updated employee directory — download now
**From**: IT Department <it@[company-lookalike].com>
```
Hi all,

The updated employee directory is available. Please download the latest version:

[DOWNLOAD DIRECTORY.xlsx]

IT Department
```
**Red Flags**: Attachment download, generic, short email

## Phish 59 — Benefits Change (MEDIUM)
**Subject**: Important change to your health insurance
**From**: [COMPANY] Benefits <benefits@[company-lookalike].com>
```
Hi [First Name],

Due to a change in our health insurance provider, all employees must re-enroll by [date + 5 days] to maintain coverage.

[RE-ENROLL NOW]

If you do not re-enroll, your coverage will lapse on [date + 7 days].

Benefits Administration
[COMPANY]
```
**Red Flags**: Health insurance = high anxiety, deadline, loss of coverage threat

## Phish 60-65 — More HR/Internal
**60** — Parking pass renewal: "Your parking permit expires Friday" | Low-threat feeling
**61** — IT system maintenance: "Log in to confirm your account before migration" | IT authority
**62** — Dress code update: "Updated dress code policy — please review and acknowledge" | Curiosity
**63** — Office closure: "Emergency office closure — work from home instructions" | Urgency
**64** — Performance review: "Your annual review has been submitted — view feedback" | Curiosity
**65** — Fire drill: "Updated evacuation procedures — acknowledge receipt" | Seems mandatory

---

# ========================================
# CATEGORY 6: TECH / SAAS (66-80)
# ========================================

## Phish 66 — DocuSign (HARD)
**Subject**: [Sender Name] sent you a document to review and sign
**From**: DocuSign <dse@docusign-mail.com>
```
[Sender Name] sent you a document

REVIEW DOCUMENT

"NDA - [COMPANY] - Confidential Agreement.pdf"

[REVIEW DOCUMENT]

Do Not Forward: This email contains a secure link to DocuSign.
Please do not share this email with others.

Powered by DocuSign
```
**Red Flags**: Very realistic format, NDA = authority/urgency, common real attack vector

## Phish 67 — Zoom Recording (MEDIUM)
**Subject**: [Coworker] shared a Zoom recording with you
**From**: Zoom <no-reply@zoom-cloud-recording.com>
```
[Coworker Name] shared a cloud recording with you.

Meeting: "Budget Discussion - Confidential"
Date: [recent date]
Duration: 43:21

[VIEW RECORDING]

Zoom Video Communications
```
**Red Flags**: Fake domain, uses real coworker name, "confidential" bait

## Phish 68 — Slack Notification (MEDIUM)
**Subject**: [Boss Name] mentioned you in #general
**From**: Slack <notification@slack-workspace.com>
```
[Boss Name] mentioned you in #general:

"Hey @[First Name], can you take a look at this ASAP?"

[VIEW MESSAGE]

You're receiving this because you have email notifications enabled.
Slack Technologies, LLC
```
**Red Flags**: Boss mention = authority/urgency, fake domain

## Phish 69 — Dropbox Shared File (MEDIUM)
**Subject**: "[First Name] — review this before tomorrow"
**From**: Dropbox <no-reply@dropbox-share.com>
```
[Sender Name] shared "Layoff Plan - Draft.pdf" with you

[VIEW FILE]

Dropbox — Keep your files safe, synced, and easy to share.
```
**Red Flags**: Explosive subject matter, urgency, fake domain

## Phish 70 — Adobe Sign (HARD)
**Subject**: Agreement ready for your signature
**From**: Adobe Sign <adobesign@adobe-echosign.com>
```
[Sender Name] ([sender@company.com]) has sent you an agreement to sign.

"Vendor Services Agreement - [COMPANY]"

[REVIEW AND SIGN]

Adobe, 345 Park Avenue, San Jose, CA 95110
```
**Red Flags**: Very realistic, e-signature phishing is extremely common

## Phish 71-75 — More Tech/SaaS
**71** — LinkedIn message: "You have 3 new connection requests" | Social curiosity
**72** — GitHub: "Security vulnerability detected in your repository" | Developer-targeted
**73** — WeTransfer: "You received files from [Name]" | File download bait
**74** — Notion: "You've been added to a workspace" | SaaS bait
**75** — Calendly: "[Name] booked a meeting with you" | Calendar bait

## Phish 76-80 — Tech Variations
**76** — Apple ID: "Your Apple ID was used to sign in on a new device" | Fear
**77** — Netflix: "Your payment method was declined" | Common consumer phish
**78** — Spotify: "Your Premium subscription has been cancelled" | Loss aversion
**79** — Windows Defender: "Threats detected on your PC — action required" | Tech support scam style
**80** — Printer/scanner: "Scanned document from HP Scanner" | Attachment-based, office realistic

---

# ========================================
# CATEGORY 7: INDUSTRY-SPECIFIC (81-90)
# ========================================

## Phish 81 — Healthcare: EHR System Alert
**Subject**: URGENT: EHR system update required
**From**: IT Department <ehr-admin@[company-lookalike].com>
```
Attention all clinical staff:

Our EHR system requires an immediate security update. Please log in to verify your credentials before the update is applied tonight at 11 PM.

[VERIFY CREDENTIALS]

Failure to verify may result in loss of access to patient records.

IT Department
```
**Red Flags**: Healthcare-specific, EHR access fear, credential harvesting

## Phish 82 — Healthcare: Insurance Verification
**Subject**: Insurance claim denied — patient [Name]
**From**: Aetna Provider Services <claims@aetna-providers.com>
```
Claim #CLM-2026-847291 for patient [Name] has been denied.

Reason: Missing pre-authorization
Amount: $4,200.00

To file an appeal, please log in to the provider portal:

[FILE APPEAL]

Aetna Provider Services
```
**Red Flags**: Revenue-related urgency, fake domain, healthcare-specific

## Phish 83 — Legal: Court Filing Notification
**Subject**: Notice of Filing — Case No. 2026-CV-04821
**From**: Maryland Judiciary <efiling@maryland-courts-system.com>
```
You have a new filing in Case No. 2026-CV-04821.

Filing Type: Motion for Summary Judgment
Filed By: Opposing Counsel
Due Date for Response: [date + 10 days]

[VIEW FILING]

Maryland Electronic Courts (MDEC)
```
**Red Flags**: Court deadline = extreme urgency for lawyers, fake domain

## Phish 84 — Legal: Client Document
**Subject**: Fwd: Signed retainer agreement — [Client Name]
**From**: [Client Name] <[client]@[client-domain-typo].com>
```
Hi [Attorney Name],

Attached is the signed retainer agreement. Please countersign and return.

[VIEW SIGNED AGREEMENT]

Thanks,
[Client Name]
```
**Red Flags**: Looks like real client communication, routine request

## Phish 85 — CPA: IRS Notice
**Subject**: IRS e-Services: Account verification required
**From**: IRS <no-reply@irs-eservices.com>
```
Your IRS e-Services account requires verification to maintain access.

PTIN: [PTIN if known]
Status: Verification Pending

[VERIFY ACCOUNT]

Failure to verify within 72 hours will result in account suspension.

Internal Revenue Service
```
**Red Flags**: IRS never emails, PTIN access fear, urgency

## Phish 86 — CPA: Client Tax Document
**Subject**: Updated W-2 for your records
**From**: [Client Name] <[client]@[lookalike].com>
```
Hi [First Name],

Here's my updated W-2. The first one had the wrong address.

[DOWNLOAD W-2.pdf]

Thanks,
[Client Name]
```
**Red Flags**: Tax season timing, looks like normal client communication, attachment

## Phish 87 — Construction: Bid Invitation
**Subject**: Invitation to Bid — [Project Name]
**From**: [GC Name] <bids@[gc-lookalike].com>
```
You are invited to submit a bid for:

Project: [Building Name] Renovation
Location: [City], MD
Bid Due: [date + 7 days]

[DOWNLOAD BID DOCUMENTS]

Please review specifications and submit via our portal.

[GC Name] Procurement
```
**Red Flags**: Industry-specific bait, bid documents = attachment malware

## Phish 88 — Real Estate: Closing Instructions
**Subject**: Updated wire instructions — [Property Address] closing
**From**: [Title Company] <closings@[title-company-typo].com>
```
Hi [First Name],

Please note the updated wire instructions for the [Property Address] closing on [date].

New wiring details are attached. Please use these instead of the previous instructions.

[VIEW WIRE INSTRUCTIONS]

Thank you,
[Title Company Name]
Settlement Department
```
**Red Flags**: This is the EXACT attack that steals millions in real estate. Wire instruction change = giant red flag.

## Phish 89 — Manufacturing: Purchase Order
**Subject**: PO #847291 — Urgent order confirmation needed
**From**: [Supplier Name] <orders@[supplier-typo].com>
```
Please confirm the attached purchase order by end of day.

PO #: 847291
Amount: $28,450.00
Ship Date: [date + 3 days]

[CONFIRM ORDER]

If not confirmed, the order will be cancelled and lead times will reset to 8 weeks.

[Supplier Name] Sales
```
**Red Flags**: Financial pressure, deadline, supply chain urgency

## Phish 90 — GovCon: CMMC Assessment Notice
**Subject**: CMMC Assessment Scheduling — [Company Name]
**From**: Cyber AB <assessments@cyberab-cmmc.com>
```
[Company Name] has been selected for a CMMC Level 2 assessment.

Assessment Window: [date range]
Assessment Organization: [Name]

To prepare, please verify your organizational information:

[VERIFY INFORMATION]

Cyber AB (The CMMC Accreditation Body)
```
**Red Flags**: Authority (assessment body), compliance fear, fake domain

---

# ========================================
# CATEGORY 8: SEASONAL / EVENT-BASED (91-100)
# ========================================

## Phish 91 — Tax Season: Refund
**Subject**: Your federal tax refund of $3,247.00 is ready
**From**: IRS <refunds@irs-tax-refund.com>
```
Your 2025 federal income tax refund has been processed.

Refund Amount: $3,247.00
Status: Ready for Direct Deposit

To receive your refund, please verify your bank information:

[VERIFY AND CLAIM REFUND]

Internal Revenue Service
Department of the Treasury
```
**Red Flags**: IRS never emails, too-good-to-be-true refund, credential harvesting

## Phish 92 — Holiday: Gift Card from Boss
**Subject**: Holiday gift for you!
**From**: [CEO Name] <[ceo]@[company-typo].com>
```
Happy holidays [First Name]!

I wanted to say thank you for all your hard work this year. Here's a small token of appreciation.

[CLAIM YOUR $100 AMAZON GIFT CARD]

Enjoy!
[CEO Name]
```
**Red Flags**: Gift card scam (extremely common), CEO impersonation, seasonal timing

## Phish 93 — Benefits: Open Enrollment
**Subject**: Open enrollment closes TOMORROW — action required
**From**: [COMPANY] Benefits <benefits@[company-typo].com>
```
Hi [First Name],

Open enrollment closes tomorrow at 5:00 PM. If you haven't made your selections, your current coverage will be cancelled.

[ENROLL NOW]

Benefits Administration
```
**Red Flags**: Coverage cancellation threat, extreme deadline

## Phish 94 — COVID/Flu: Vaccine Requirement
**Subject**: Required: Submit vaccination status by Friday
**From**: [COMPANY] HR <hr-compliance@[company-typo].com>
```
Per company policy, all employees must submit their updated vaccination status.

[SUBMIT STATUS]

Non-compliance may affect your employment status.

HR Compliance
```
**Red Flags**: Health data harvesting, employment threat, authority

## Phish 95 — Black Friday: IT Purchase
**Subject**: IT approved purchase — claim your new laptop
**From**: IT Department <it-procurement@[company-typo].com>
```
Hi [First Name],

Your request for a new laptop has been approved. Please confirm your shipping address and preferred model:

[CONFIRM AND CLAIM]

IT Procurement
```
**Red Flags**: Who doesn't want a new laptop? Excitement-based social engineering

## Phish 96 — Year-End: W-2 Available
**Subject**: Your 2025 W-2 is now available
**From**: [COMPANY] Payroll <w2@[company-typo].com>
```
Your 2025 W-2 tax form is now available for download.

[DOWNLOAD W-2]

Please log in with your employee credentials to access your tax documents.

Payroll Department
```
**Red Flags**: Seasonal timing (January), everyone needs their W-2, credential harvesting

## Phish 97 — Summer: AC Maintenance Scam
**Subject**: Building HVAC maintenance — confirm your office location
**From**: Facilities <facilities@[company-typo].com>
```
We're scheduling HVAC maintenance for next week. Please confirm your office/desk location so we can ensure minimal disruption:

[CONFIRM LOCATION]

Facilities Management
```
**Red Flags**: Innocent-seeming, data harvesting, building authority

## Phish 98 — New Year: Policy Updates
**Subject**: Updated company policies for 2026 — acknowledge by Friday
**From**: [COMPANY] Legal <legal@[company-typo].com>
```
Hi [First Name],

Please review and acknowledge the updated company policies for 2026:

- Remote Work Policy (revised)
- Acceptable Use Policy (revised)
- Data Handling Procedures (new)

[REVIEW AND ACKNOWLEDGE]

Failure to acknowledge by Friday may result in restricted system access.

Legal & Compliance
```
**Red Flags**: Mandatory acknowledgment, access restriction threat, routine-looking

## Phish 99 — Breaking News: Data Breach
**Subject**: URGENT: [COMPANY] may have been affected by a data breach
**From**: IT Security <security@[company-typo].com>
```
We are investigating a potential data breach that may affect employee accounts.

As a precaution, all employees must reset their passwords immediately:

[RESET PASSWORD NOW]

Do not use your current password on any other accounts until this investigation is complete.

IT Security Team
[COMPANY]
```
**Red Flags**: Irony — phishing email about a breach, extreme urgency, credential harvesting

## Phish 100 — The Classic: Nigerian Prince (EASY — for fun/baseline)
**Subject**: URGENT BUSINESS PROPOSAL — $4.5 MILLION USD
**From**: Barrister Ahmed <barrister.ahmed@diplomat-funds.com>
```
Dear Sir/Madam,

I am Barrister Ahmed representing the estate of a deceased client who left $4,500,000 in an unclaimed account. I am seeking a trustworthy partner to assist with the transfer of these funds. You will receive 30% as compensation.

Please reply with your full name, phone number, and bank details to proceed.

Yours faithfully,
Barrister Ahmed, Esq.
```
**Red Flags**: Everything. If anyone clicks this, they need extra training.

---

# ========================================
# DEPLOYMENT GUIDE
# ========================================

## Option 1: GoPhish (Free, Open Source — RECOMMENDED)
- Install on your server: `apt install gophish` or Docker
- URL: github.com/gophish/gophish
- Import these templates
- Set up landing pages that mimic login portals
- Track: who clicked, who submitted credentials, who reported
- Generates reports per campaign

## Option 2: n8n Workflow
- Build a workflow that sends these via SMTP
- Track clicks via unique URLs per employee
- Log results to a spreadsheet or database
- Less polished than GoPhish but uses your existing infrastructure

## Option 3: KnowBe4 / Proofpoint (Paid)
- If clients want a branded solution
- KnowBe4 starts at ~$18/user/year
- Can white-label as a Palisade One service

## How to Run Phishing Simulations as a Service

### For Clients:
1. Include phishing simulation in DEFEND ($599) and DOMINATE ($899) tiers
2. Run monthly campaigns (different template each month)
3. Start with EASY templates, progress to HARD over 3 months
4. Send results report to client — shows improvement over time
5. Anyone who clicks gets auto-enrolled in training module

### Pricing (standalone):
- $5-10/employee/month as an add-on
- Or bundle into existing tiers (recommended — adds value)

### Campaign Schedule (Monthly):
| Month | Difficulty | Category | Template |
|-------|-----------|----------|----------|
| 1 | Easy | Shipping | #41 FedEx |
| 2 | Easy | Microsoft | #1 Password Expiry |
| 3 | Medium | Internal | #52 Mandatory Training |
| 4 | Medium | Financial | #30 Invoice |
| 5 | Medium | Tech | #66 DocuSign |
| 6 | Hard | Internal | #51 Salary Increase |
| 7 | Hard | Microsoft | #3 MFA Reset |
| 8 | Hard | Financial | #29 CEO Wire Transfer |
| 9 | Hard | Internal | #56 Bonus Payout |
| 10 | Hard | Industry | Use industry-specific |
| 11 | Hard | Mixed | #99 Data Breach |
| 12 | Easy | Baseline | #100 Nigerian Prince (re-test) |
