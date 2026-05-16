# BoostNG Assistant Bot 🤖
**By Mayor Tech Inc © 2026**

A WhatsApp security and assistant bot for BoostNG staff numbers.

## Features
- 🛡️ Security scanning (crash text, zalgo, phishing, spam blocking)
- ✅ Channel join verification before access
- 🤖 AI powered replies (Groq - Llama 3.3)
- 📋 Interactive menu system
- 👨‍💼 Staff routing (online/offline)
- 💧 Mayor Tech watermark on every message
- 🔄 Auto reconnect if disconnected

## Deploy on Railway

### Step 1 — Push to GitHub
1. Create a new GitHub repo called `boostng-bot`
2. Upload all these files to it

### Step 2 — Deploy on Railway
1. Go to railway.app
2. Click **New Project** → **Deploy from GitHub**
3. Select your `boostng-bot` repo
4. Railway will auto-detect Node.js and deploy

### Step 3 — Add Environment Variables
In Railway dashboard → your project → **Variables**:
```
GROQ_API_KEY=your_groq_key
STAFF1_NUMBER=2348012345678
STAFF2_NUMBER=2348087654321
(etc for all 5 staff)
```

### Step 4 — Scan QR Code
1. Go to Railway → **Deployments** → **View Logs**
2. A QR code will appear in the logs
3. Open WhatsApp on the bot's phone
4. Go to **Linked Devices** → **Link a Device**
5. Scan the QR code
6. Bot is now LIVE! ✅

## Staff Management
To set staff online/offline, edit the STAFF array in index.js:
```js
{ id: 'staff1', name: 'John', number: '2348012345678', online: true }
```
Set `online: true` when staff is available, `false` when not.

## Menu Options
Users get this menu after typing JOINED:
- 1️⃣ Place SMM Order
- 2️⃣ Check Order Status
- 3️⃣ Top Up Wallet
- 4️⃣ Virtual Numbers
- 5️⃣ Pricing & Services
- 6️⃣ Referral Program
- 7️⃣ Talk to Staff
- 8️⃣ Our Links & Channels
- 0️⃣ About BoostNG

## Security Features
The bot blocks:
- 💥 WhatsApp crash text
- 🔤 Zalgo/corrupted characters
- 📏 Oversized messages (>5000 chars)
- 🔗 Phishing links
- 🔴 Spam (8+ messages per minute → 5min temp block)
- 📱 RTL/invisible character attacks

© 2026 MAYOR TECH INC — ALL RIGHTS RESERVED
