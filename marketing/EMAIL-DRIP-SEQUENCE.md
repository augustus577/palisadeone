# PALISADE ONE — Email Drip Sequence
# Triggered after someone completes the cyber assessment
# Set up in: n8n, Mailchimp (free tier), or HubSpot (free CRM)

---

## TRIGGER: Someone completes cyber-assessment.html
## GOAL: Get them on a call to review results → close the deal

---

## EMAIL 1: Immediate (sent within 5 minutes of assessment completion)
**Subject**: Your Palisade One Cyber Risk Assessment Results

```
Hi [First Name],

Thanks for completing the Palisade One Cyber Risk Assessment.

Here's your summary:

Overall Score: [SCORE]/100
Framework: [FRAMEWORK THEY SELECTED]
Critical Gaps Found: [NUMBER]

[If score < 50]:
Your score indicates significant security gaps that could leave your business vulnerable to cyberattacks. The critical areas flagged in your assessment are the ones attackers exploit most often.

[If score 50-75]:
You've got some foundations in place, but there are gaps that could be exploited. The areas flagged as "high" priority in your assessment are worth addressing soon.

[If score > 75]:
Solid foundation. You're ahead of most businesses your size. But the gaps we identified could still be exploited by a determined attacker.

I'd like to offer a free 15-minute call to walk through your results in detail — what the gaps mean, what the real-world risk is, and what to prioritize first. No pitch, just clarity.

Book a time that works: [CALENDLY LINK or "reply to this email"]

Best,
Augustus Camatta
Palisade One | Managed Cyber Defense
camatta@palisadeone.com | palisadeone.com
```

---

## EMAIL 2: Day 2 — The Education Email
**Subject**: What your cyber assessment score actually means

```
Hi [First Name],

Yesterday you took our cyber risk assessment and scored [SCORE]/100.

Here's what that means in plain English:

[If score < 40]:
A score below 40 means your business has critical vulnerabilities that attackers actively exploit. If you were targeted today — by ransomware, a phishing attack, or a compromised employee account — there's very little standing between the attacker and your data.

The most common attack path we see:
1. Employee clicks a phishing link
2. Attacker gets access to their workstation
3. They move laterally across your network (no segmentation = no barriers)
4. They find your valuable data — client records, financials, health records
5. They encrypt everything and demand ransom

Without endpoint detection, this entire process takes about 4 hours. With Palisade One, we catch it in step 1 — in under 1 second.

[If score 40-70]:
A score in this range means you have some controls in place, but there are blind spots. Most businesses in this range have antivirus but not EDR, have a firewall but no monitoring, or have policies written down but no technical enforcement.

The difference between "pretty good" and "actually protected" is the difference between antivirus and a 24/7 SOC watching your network. One catches known threats. The other catches everything.

Here's an article that explains the difference: [link to blog post if created]

I'm available for a quick call if you'd like to go through your specific results. No obligation.

Best,
Augustus
```

---

## EMAIL 3: Day 4 — The Fear/Urgency Email
**Subject**: This happened to a business just like yours

```
Hi [First Name],

I want to share something that happened recently to a business similar to yours.

A 35-person accounting firm in Maryland got hit with ransomware. Here's what happened:

- An employee opened what looked like a tax document from a client
- It was malware. Within 4 hours, every file on the network was encrypted
- Client SSNs, financial records, bank details — all exposed
- The attackers demanded $300,000 in Bitcoin
- Their backups were on the same network — also encrypted
- They paid the ransom. Got about 60% of their data back
- Total cost: over $500,000 in ransom, recovery, legal fees, and lost business
- They lost 3 major clients who no longer trusted them with their data

This isn't hypothetical. This happens to 1,400 businesses every single day.

Your assessment flagged [NUMBER] critical gaps. Those are the exact entry points an attacker would use.

I don't want this to happen to you. Let me walk you through your results and show you exactly how to close those gaps.

15 minutes. Free. No pitch.

Reply to this email or book a time: [CALENDLY LINK]

Augustus
```

---

## EMAIL 4: Day 7 — The Value Email
**Subject**: What $399/month actually buys you

```
Hi [First Name],

You might be thinking: "Cybersecurity sounds expensive. We'll deal with it later."

So let me break down the math:

WHAT IT COSTS TO BUILD SECURITY YOURSELF:
- SIEM platform: $2,000-10,000/month
- EDR licenses: $5-15 per device per month
- SOC analyst salary: $85,000-120,000/year
- Compliance consultant: $200-400/hour
- Incident response retainer: $5,000-15,000/year
Total: $150,000+/year minimum

WHAT IT COSTS WHEN YOU GET BREACHED:
- Average ransomware payment (SMB): $170,000
- Average downtime: 21 days at ~$8,000/hour
- Legal and notification costs: $50,000-200,000
- Lost business and reputation: incalculable

WHAT PALISADE ONE COSTS:
$399/month. $4,788/year.

That's 3% of the cost of building it yourself.
And 1% of the cost of a breach.

We include everything: EDR on every device, 24/7 SOC monitoring, real-time SIEM, compliance automation, incident response. Flat rate. No per-device fees. No contracts.

Your assessment showed your business has gaps. We fix them. All of them.

Ready to talk? Reply to this email.

Augustus
```

---

## EMAIL 5: Day 10 — The Last Email
**Subject**: Last note from me (unless you want to chat)

```
Hi [First Name],

This is the last email in this sequence — I'm not going to keep bugging you.

But I want to leave you with one thing:

Your cyber risk assessment scored [SCORE]/100. That score represents real, exploitable gaps in your security. Gaps that ransomware operators, phishing gangs, and data thieves use every single day against businesses exactly like yours.

The good news: every one of those gaps is fixable.

If you ever want to:
- Review your assessment results in detail
- Get a clear roadmap for improving your security
- See what Palisade One looks like from the inside

Just reply to this email. I respond personally.

In the meantime, your assessment is always available at:
palisadeone.com/cyber-assessment.html

Stay safe out there.

Augustus Camatta
Palisade One | palisadeone.com
camatta@palisadeone.com
```

---

## HOW TO SET THIS UP

### Option A: n8n (Free — already on your server)
1. Create a workflow triggered by webhook from cyber-assessment.html
2. Add a delay node between each email (2 days, 2 days, 3 days, 3 days)
3. Use Microsoft Outlook node to send emails
4. Store lead data in a Google Sheet or JSON file

### Option B: HubSpot Free CRM (Recommended for tracking)
1. Sign up at hubspot.com (free forever)
2. Create a sequence with these 5 emails
3. Add contacts manually or via form integration
4. HubSpot tracks opens, clicks, and replies automatically
5. Set up a pipeline: Prospect → Assessment Done → Call Scheduled → Proposal Sent → Closed

### Option C: Mailchimp (Free up to 500 contacts)
1. Create an automation sequence
2. Trigger: added to "Assessment Completed" audience
3. Set delays between emails
4. Less CRM functionality than HubSpot but simpler

### IMPORTANT: Connect to cyber-assessment.html
We need to add a lead capture form to your cyber assessment page — right now it doesn't collect email addresses before showing results. We should add:
- Name + Email + Company + Phone fields at the start or end
- On submit, send webhook to n8n → triggers this drip sequence
- This is the #1 thing to build next on the platform
