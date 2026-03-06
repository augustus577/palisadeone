# n8n Social Media Automation — Setup Guide

## Overview
We're building an n8n workflow that auto-posts to LinkedIn, X (Twitter), Facebook, and Instagram.
Your n8n instance: http://soc.palisadeone.com:5678

---

## STEP 1: Get API Credentials for Each Platform

### X (Twitter) API
1. Go to https://developer.twitter.com/en/portal/petition/essential/basic-info
2. Sign up for a **Free** developer account (allows 1,500 tweets/month — plenty)
3. Create a new Project + App
4. App name: "PalisadeOne Social"
5. Go to your app → Keys and Tokens tab
6. Generate and save:
   - API Key (Consumer Key)
   - API Secret (Consumer Secret)
   - Access Token
   - Access Token Secret
7. In App Settings → User Authentication Settings → Set up:
   - App permissions: Read and Write
   - Type: Web App
   - Callback URL: http://soc.palisadeone.com:5678/rest/oauth2-credential/callback
   - Website URL: https://palisadeone.com

### LinkedIn API
1. Go to https://www.linkedin.com/developers/apps
2. Create a new app:
   - App name: PalisadeOne Social
   - LinkedIn Page: (select your company page — create it first!)
   - App logo: use your hexagon logo
3. Under "Auth" tab, add redirect URL:
   http://soc.palisadeone.com:5678/rest/oauth2-credential/callback
4. Under "Products" tab, request access to:
   - "Share on LinkedIn" (for posting)
   - "Sign In with LinkedIn using OpenID Connect"
5. Save your:
   - Client ID
   - Client Secret
6. NOTE: LinkedIn app review can take a few days. For immediate posting, you can use the manual share approach or post via the LinkedIn UI initially.

### Facebook Page API
1. Go to https://developers.facebook.com/
2. Create a new app → Business type
3. App name: PalisadeOne Social
4. Add "Facebook Login" product
5. Go to: https://developers.facebook.com/tools/explorer/
6. Select your app
7. Get User Token → check permissions:
   - pages_manage_posts
   - pages_read_engagement
   - publish_to_groups (optional)
8. Click "Generate Access Token" → authorize
9. Exchange for long-lived token:
   GET https://graph.facebook.com/v19.0/oauth/access_token?grant_type=fb_exchange_token&client_id={APP_ID}&client_secret={APP_SECRET}&fb_exchange_token={SHORT_TOKEN}
10. Get Page Access Token:
    GET https://graph.facebook.com/v19.0/me/accounts?access_token={LONG_LIVED_TOKEN}
11. Save:
    - Page ID
    - Page Access Token (long-lived)

### Instagram API (via Facebook)
- Instagram posting requires a Facebook Business Page linked to your Instagram Business Account
- Uses the same Facebook app from above
- After linking accounts in Instagram settings:
  GET https://graph.facebook.com/v19.0/{page-id}?fields=instagram_business_account&access_token={PAGE_TOKEN}
- Save the Instagram Business Account ID

---

## STEP 2: Import Workflows into n8n

1. Open n8n at http://soc.palisadeone.com:5678
2. Login: camatta@palisadeone.com / PalisadeOne2026!
3. Click the menu (top left) → Import from File
4. Import each workflow JSON file from this folder:
   - `social-poster-x.json` — Posts to X/Twitter
   - `social-poster-linkedin.json` — Posts to LinkedIn
   - `social-poster-facebook.json` — Posts to Facebook
   - `social-poster-master.json` — Master scheduler that triggers all platforms
5. After importing, configure credentials in each workflow (click the node → set credentials)

---

## STEP 3: Add Content Queue

The master workflow reads from a simple content queue. You can:

**Option A: Manual** — Trigger the workflow manually and type the post content
**Option B: Schedule** — Pre-load posts into the workflow's static data and it posts on schedule
**Option C: Webhook** — Call a webhook URL with post content (I can build a simple web form for this)

---

## STEP 4: Test

1. Open each workflow in n8n
2. Click "Execute Workflow"
3. Verify posts appear on each platform
4. Activate the workflow (toggle ON) for automatic scheduling

---

## Troubleshooting

- **401 errors**: Credentials are wrong or expired. Regenerate tokens.
- **403 errors**: App doesn't have the right permissions. Check scopes.
- **LinkedIn not posting**: App review might be pending. Wait or post manually.
- **Instagram not posting**: Make sure Instagram account is "Business" type and linked to Facebook Page.
- **Rate limits**: Twitter free tier = 1,500 tweets/month. LinkedIn = 100 posts/day. Facebook = no practical limit.
