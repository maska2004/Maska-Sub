# Maska Sub — Data Bundle Reselling Storefront

A working storefront where customers pick a network + data plan, enter their
phone number, and pay via Paystack. Built with a plain HTML/CSS/JS frontend
and a small Node/Express backend (the backend is required because payment
verification needs a secret key that must never sit in the browser).

## What this does right now
- Shows data plans by network (MTN, Glo, Airtel, 9mobile — edit freely)
- Takes real payment through Paystack
- Logs every order to `orders.json`
- Marks paid orders as "needs manual fulfillment" until you connect a real
  VTU provider (see below)

## What you need before it works

1. **Node.js installed** on your computer (or the hosting service you deploy to)
2. **A free Paystack account** → https://paystack.com
   - Go to Settings → API Keys & Webhooks
   - Copy your **Public Key** and **Secret Key** (use the **test** keys first)
3. **(Later) A VTU provider account** — this is what actually delivers the
   data to a phone number. Popular Nigerian options to look into:
   VTpass, ClubKonnect, Sabipay. Until you connect one, paid orders just
   get logged for you to fulfill by hand (you'd manually buy/send the data
   using whatever method you currently use).

## Setup

```bash
# 1. Install dependencies
npm install

# 2. Copy the example environment file
cp .env.example .env

# 3. Open .env and fill in:
#    - PAYSTACK_PUBLIC_KEY
#    - PAYSTACK_SECRET_KEY
#    - ADMIN_KEY (make up any password — used to view orders)

# 4. Start the server
npm start
```

Then open **http://localhost:3000** in your browser.

## Editing your data plans & prices

Open `plans.json`. Each plan looks like this:

```json
{ "id": "mtn-1gb", "network": "MTN", "label": "1GB - 30 Days", "costPriceNaira": 480, "sellPriceNaira": 600 }
```

- `costPriceNaira` — what it costs *you* (from your VTU provider). Not shown to customers.
- `sellPriceNaira` — what the customer pays. Your profit is the gap between the two.

**Important:** the example prices in this file are placeholders. Replace them
with real prices once you have a VTU provider account.

## Viewing orders (to fulfill manually for now)

Visit:
```
http://localhost:3000/api/admin/orders?key=YOUR_ADMIN_KEY
```
(use the `ADMIN_KEY` you set in `.env`)

This shows every order — paid, pending, or failed — so you know who to send
data to until automatic fulfillment is connected.

## Connecting a real VTU provider later

Open `server.js` and find the `fulfillOrder` function near the bottom —
it has a commented example showing exactly where to plug in a real API call
once you sign up with a provider. Their documentation will give you the
exact request format to use.

## Putting this online (so customers can actually reach it)

This needs to run on a server, not just your laptop, for real customers to
use it. Free/cheap options that work well for a small Node app:
- **Render.com** (has a free tier)
- **Railway.app**
- **Fly.io**

All three let you connect a GitHub repo and deploy in a few clicks — upload
this project to GitHub first, then connect it. Remember to add your `.env`
values in their dashboard's "Environment Variables" section (never upload
your real `.env` file to GitHub).

## Switching from test to real payments

Once you're confident everything works, swap your Paystack **test** keys for
your **live** keys in `.env` (Paystack requires business verification first —
check their dashboard for what's needed).
