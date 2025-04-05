require('dotenv').config();
const axios = require('axios');
const ethers = require('ethers');
const crypto = require('crypto');
const fs = require('fs');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const userAgents = require('user-agents');

const DELAY_BETWEEN_WALLETS = 2000;
const MAX_RETRIES = 3;
const CHECK_INTERVAL = 60 * 1000;

let privateKeys = [];
if (process.env.PRIVATE_KEY) {
  if (process.env.PRIVATE_KEY.includes(',')) {
    privateKeys = process.env.PRIVATE_KEY.split(',').map(key => key.trim());
  } else {
    privateKeys.push(process.env.PRIVATE_KEY);
  }
}

let keyIndex = 1;
while (process.env[`PRIVATE_KEY_${keyIndex}`]) {
  privateKeys.push(process.env[`PRIVATE_KEY_${keyIndex}`]);
  keyIndex++;
}

if (privateKeys.length === 0) {
  console.error('\x1b[31m%s\x1b[0m', '❌ Error: No private keys found in .env');
  process.exit(1);
}

console.log(`\n📋 Loaded ${privateKeys.length} private keys from .env`);

let proxies = [];
try {
  if (fs.existsSync('./proxies.txt')) {
    const proxiesContent = fs.readFileSync('./proxies.txt', 'utf8');
    proxies = proxiesContent
      .split('\n')
      .map(proxy => proxy.trim())
      .filter(proxy => proxy && !proxy.startsWith('#'));
    console.log(`🌐 Loaded ${proxies.length} proxies from proxies.txt`);
  }
} catch (error) {
  console.error('\x1b[33m%s\x1b[0m', `⚠️ Error loading proxies.txt: ${error.message}`);
}

function createProxyAgent(proxyString) {
  if (!proxyString) return null;
  try {
    if (proxyString.startsWith('socks://') || proxyString.startsWith('socks4://') || proxyString.startsWith('socks5://')) {
      return new SocksProxyAgent(proxyString);
    }
    let formattedProxy = proxyString;
    if (!formattedProxy.includes('://')) {
      if (formattedProxy.includes('@') || !formattedProxy.match(/^\d+\.\d+\.\d+\.\d+:\d+$/)) {
        formattedProxy = `http://${formattedProxy}`;
      } else {
        const [host, port] = formattedProxy.split(':');
        formattedProxy = `http://${host}:${port}`;
      }
    }
    return new HttpsProxyAgent(formattedProxy);
  } catch (error) {
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Error creating proxy agent for ${proxyString}: ${error.message}`);
    return null;
  }
}

function getRandomUserAgent() {
  const ua = new userAgents({ deviceCategory: 'desktop' });
  return ua.toString();
}

async function startSynthelixNodeForWallet(privateKey, proxyString, walletLabel, retryCount = 0) {
  const wallet = new ethers.Wallet(privateKey);
  const address = wallet.address;
  const proxyAgent = proxyString ? createProxyAgent(proxyString) : null;
  const userAgent = getRandomUserAgent();

  console.log('\x1b[36m%s\x1b[0m', `\n🔄 Starting Synthelix node for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}${proxyString ? ' (using proxy)' : ''}`);

  const axiosConfig = {
    httpsAgent: proxyAgent,
    httpAgent: proxyAgent
  };

  try {
    let cookies = '';
    let csrfToken = '';
    const commonHeaders = {
      'accept': '*/*',
      'content-type': 'application/json',
      'user-agent': userAgent,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'Referer': 'https://dashboard.synthelix.io/'
    };

    process.stdout.write('\x1b[90m[1/6]\x1b[0m Fetching auth providers... ');
    const providersResponse = await axios.get('https://dashboard.synthelix.io/api/auth/providers', {
      ...axiosConfig,
      headers: commonHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    if (providersResponse.headers['set-cookie']) {
      cookies = providersResponse.headers['set-cookie'].join('; ');
    }

    process.stdout.write('\x1b[90m[2/6]\x1b[0m Getting CSRF token... ');
    const csrfResponse = await axios.get('https://dashboard.synthelix.io/api/auth/csrf', {
      ...axiosConfig,
      headers: { ...commonHeaders, 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    csrfToken = csrfResponse.data.csrfToken;
    if (csrfResponse.headers['set-cookie']) {
      cookies = [...(cookies ? [cookies] : []), ...csrfResponse.headers['set-cookie']].join('; ');
    }

    process.stdout.write('\x1b[90m[3/6]\x1b[0m Preparing message signature... ');
    const nonce = generateRandomString(32);
    const requestId = Date.now().toString();
    const issuedAt = new Date().toISOString();
    const domain = { name: "Synthelix", version: "1", chainId: 1, verifyingContract: "0x0000000000000000000000000000000000000000" };
    const types = { Authentication: [{ name: "address", type: "address" }, { name: "statement", type: "string" }, { name: "nonce", type: "string" }, { name: "requestId", type: "string" }, { name: "issuedAt", type: "string" }] };
    const value = { address, statement: "Sign in to enter Synthelix Dashboard.", nonce, requestId, issuedAt };

    let signature;
    try {
      if (typeof wallet.signTypedData === 'function') {
        signature = await wallet.signTypedData(domain, types, value);
      } else if (typeof wallet._signTypedData === 'function') {
        signature = await wallet._signTypedData(domain, types, value);
      } else {
        const messageString = JSON.stringify({ domain, types, value });
        signature = await wallet.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(messageString))));
      }
    } catch (err) {
      const messageToSign = `${address}:${value.statement}:${value.nonce}:${value.requestId}:${value.issuedAt}`;
      signature = await wallet.signMessage(messageToSign);
    }
    console.log('\x1b[32m%s\x1b[0m', '✓');

    process.stdout.write('\x1b[90m[4/6]\x1b[0m Authenticating with web3... ');
    const authData = new URLSearchParams({
      address, signature, domain: JSON.stringify(domain), types: JSON.stringify(types), value: JSON.stringify(value),
      redirect: 'false', callbackUrl: '/', csrfToken, json: 'true'
    });
    const authResponse = await axios.post('https://dashboard.synthelix.io/api/auth/callback/web3', authData.toString(), {
      ...axiosConfig,
      headers: { ...commonHeaders, 'content-type': 'application/x-www-form-urlencoded', 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    if (authResponse.headers['set-cookie']) {
      cookies = [...(cookies ? [cookies] : []), ...authResponse.headers['set-cookie']].join('; ');
    }

    process.stdout.write('\x1b[90m[5/6]\x1b[0m Getting session... ');
    const sessionResponse = await axios.get('https://dashboard.synthelix.io/api/auth/session', {
      ...axiosConfig,
      headers: { ...commonHeaders, 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    if (sessionResponse.headers['set-cookie']) {
      cookies = [...(cookies ? [cookies] : []), ...sessionResponse.headers['set-cookie']].join('; ');
    }

    const pointsInfo = await getPointsInfo(cookies, commonHeaders, axiosConfig);
    console.log('\x1b[36m%s\x1b[0m', `💎 Total Points Before: ${pointsInfo.totalPoints || 0}`);

    const statusInfo = await getNodeStatus(cookies, commonHeaders, axiosConfig);
    if (statusInfo.nodeRunning) {
      process.stdout.write('\x1b[90m[+]\x1b[0m Stopping existing node first... ');
      try {
        const timeRunningHours = statusInfo.currentEarnedPoints / statusInfo.pointsPerHour;
        await axios.post('https://dashboard.synthelix.io/api/node/stop', {
          claimedHours: timeRunningHours,
          pointsEarned: statusInfo.currentEarnedPoints
        }, { ...axiosConfig, headers: { ...commonHeaders, 'Cookie': cookies } });
        console.log('\x1b[32m%s\x1b[0m', '✓');
        console.log('\x1b[32m%s\x1b[0m', `💰 Claimed ${statusInfo.currentEarnedPoints} points from running node`);
        await delay(1000);
      } catch (error) {
        console.log('\x1b[31m%s\x1b[0m', '❌');
        console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to stop node: ${error.message}`);
      }
    }

    process.stdout.write('\x1b[90m[6/6]\x1b[0m Starting node... ');
    await axios.post('https://dashboard.synthelix.io/api/node/start', null, {
      ...axiosConfig,
      headers: { ...commonHeaders, 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    console.log('\x1b[32m%s\x1b[0m', `✅ Node started successfully for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}!\n`);

    await claimDailyRewards(address, cookies, commonHeaders, axiosConfig, walletLabel);
    const updatedStatusInfo = await getNodeStatus(cookies, commonHeaders, axiosConfig);
    const updatedPointsInfo = await getPointsInfo(cookies, commonHeaders, axiosConfig);

    console.log('\x1b[33m%s\x1b[0m', `\n📊 Node Status for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}:`);
    console.log('\x1b[33m%s\x1b[0m', `🔄 Node Running: ${updatedStatusInfo.nodeRunning ? 'Yes' : 'No'}`);
    console.log('\x1b[33m%s\x1b[0m', `⏱️ Time Left: ${formatTime(updatedStatusInfo.timeLeft)}`);
    console.log('\x1b[33m%s\x1b[0m', `💰 Current Points: ${updatedStatusInfo.currentEarnedPoints || 0}`);
    console.log('\x1b[33m%s\x1b[0m', `💸 Points Per Hour: ${updatedStatusInfo.pointsPerHour || 0}`);
    console.log('\x1b[33m%s\x1b[0m', `💎 Total Points: ${updatedPointsInfo.totalPoints || 0}`);
    console.log('\x1b[33m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

    return {
      success: true, address, cookies, commonHeaders, axiosConfig,
      timeLeft: updatedStatusInfo.timeLeft, statusInfo: updatedStatusInfo,
      pointsInfo: updatedPointsInfo, walletLabel
    };
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[31m%s\x1b[0m', `❌ Error starting node for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}: ${error.message}`);
    if (retryCount < MAX_RETRIES) {
      console.log('\x1b[33m%s\x1b[0m', `⚠️ Retrying ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)} (Attempt ${retryCount + 1}/${MAX_RETRIES})...`);
      await delay(5000);
      return startSynthelixNodeForWallet(privateKey, proxyString, walletLabel, retryCount + 1);
    }
    return { success: false, address, error: error.message, walletLabel };
  }
}

async function claimDailyRewards(address, cookies, commonHeaders, axiosConfig, walletLabel) {
  try {
    process.stdout.write('\x1b[90m[+]\x1b[0m Claiming daily rewards... ');
    const updatedHeaders = { ...commonHeaders, 'Cookie': cookies, 'Referer': 'https://dashboard.synthelix.io/' };
    await axios.post('https://dashboard.synthelix.io/api/rew/dailypoints', { points: 1000 }, {
      ...axiosConfig,
      headers: updatedHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    console.log('\x1b[32m%s\x1b[0m', `💰 Claimed 1000 daily points for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}`);
    return true;
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to claim daily rewards: ${error.message}`);
    if (error.response && error.response.data && error.response.data.error === 'Already claimed today') {
      console.log('\x1b[33m%s\x1b[0m', `ℹ️ Daily rewards already claimed for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}`);
    }
    return false;
  }
}

async function getNodeStatus(cookies, commonHeaders, axiosConfig) {
  try {
    process.stdout.write('\x1b[90m[+]\x1b[0m Getting node status... ');
    const updatedHeaders = { ...commonHeaders, 'Cookie': cookies, 'Referer': 'https://dashboard.synthelix.io/' };
    const response = await axios.get('https://dashboard.synthelix.io/api/node/status', {
      ...axiosConfig,
      headers: updatedHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    return response.data;
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to get node status: ${error.message}`);
    return { nodeRunning: false, timeLeft: 0, currentEarnedPoints: 0, pointsPerHour: 0 };
  }
}

async function getPointsInfo(cookies, commonHeaders, axiosConfig) {
  try {
    process.stdout.write('\x1b[90m[+]\x1b[0m Getting points info... ');
    const updatedHeaders = {
      ...commonHeaders,
      'accept': '*/*',
      'accept-language': 'en-US,en;q=0.8',
      'sec-ch-ua': '"Brave";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-gpc': '1',
      'Cookie': cookies,
      'Referer': 'https://dashboard.synthelix.io/'
    };
    const response = await axios.get('https://dashboard.synthelix.io/api/get/points', {
      ...axiosConfig,
      headers: updatedHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    return { totalPoints: response.data.points || 0 };
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to get points info: ${error.message}`);
    return { totalPoints: 0 };
  }
}

function formatTime(seconds) {
  if (!seconds) return '0s';
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = Math.floor(seconds % 60);
  let result = '';
  if (hours > 0) result += `${hours}h `;
  if (minutes > 0 || hours > 0) result += `${minutes}m `;
  result += `${remainingSeconds}s`;
  return result.trim();
}

function generateRandomString(length) {
  return crypto.randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length)
    .replace(/[^a-zA-Z0-9]/g, '')
    .replace(/(.{1,4})/g, (m) => Math.random() > 0.5 ? m.toUpperCase() : m);
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function monitorAndRestartNodes() {
  const walletSessions = {};

  for (let i = 0; i < privateKeys.length; i++) {
    const privateKey = privateKeys[i];
    const walletLabel = `Wallet ${i + 1}`;
    const proxy = proxies.length > 0 ? proxies[i % proxies.length] : null;
    const result = await startSynthelixNodeForWallet(privateKey, proxy, walletLabel);
    if (result.success) {
      walletSessions[result.address] = result;
    }
    if (i < privateKeys.length - 1) await delay(DELAY_BETWEEN_WALLETS);
  }

  while (true) {
    console.clear();

    console.log('\x1b[36m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log('\x1b[36m%s\x1b[0m', `  SYNTHELIX BOT`);
    console.log('\x1b[36m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
    console.log(`🔍 Checking ${privateKeys.length} wallets at ${new Date().toLocaleString()}\n`);

    let activeWallets = 0;

    for (let i = 0; i < privateKeys.length; i++) {
      const privateKey = privateKeys[i];
      const wallet = new ethers.Wallet(privateKey);
      const address = wallet.address;
      const walletLabel = `Wallet ${i + 1}`;
      const shortAddress = `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
      const proxy = proxies.length > 0 ? proxies[i % proxies.length] : null;

      try {
        if (walletSessions[address] && walletSessions[address].cookies) {
          const session = walletSessions[address];
          const statusInfo = await getNodeStatus(session.cookies, session.commonHeaders, session.axiosConfig);
          const pointsInfo = await getPointsInfo(session.cookies, session.commonHeaders, session.axiosConfig);

          console.log('\x1b[36m%s\x1b[0m', `${walletLabel}: ${shortAddress}`);
          console.log('\x1b[33m%s\x1b[0m', `Status: ${statusInfo.nodeRunning ? 'Running' : 'Stopped'}`);
          console.log('\x1b[33m%s\x1b[0m', `Time Left: ${formatTime(statusInfo.timeLeft)}`);
          console.log('\x1b[33m%s\x1b[0m', `Current Points: ${statusInfo.currentEarnedPoints || 0}`);
          console.log('\x1b[33m%s\x1b[0m', `Points/Hour: ${statusInfo.pointsPerHour || 0}`);
          console.log('\x1b[33m%s\x1b[0m', `Total Points: ${pointsInfo.totalPoints || 0}`);
          console.log('');

          if (statusInfo.nodeRunning) activeWallets++;

          if (!statusInfo.nodeRunning || statusInfo.timeLeft < 600) {
            console.log('\x1b[33m%s\x1b[0m', `⚠️ Node needs restart for ${walletLabel}: ${shortAddress}`);
            if (statusInfo.nodeRunning && statusInfo.currentEarnedPoints > 0) {
              process.stdout.write('\x1b[90m[+]\x1b[0m Stopping node to claim points... ');
              try {
                const timeRunningHours = statusInfo.currentEarnedPoints / statusInfo.pointsPerHour;
                await axios.post('https://dashboard.synthelix.io/api/node/stop', {
                  claimedHours: timeRunningHours,
                  pointsEarned: statusInfo.currentEarnedPoints
                }, { ...session.axiosConfig, headers: { ...session.commonHeaders, 'Cookie': session.cookies } });
                console.log('\x1b[32m%s\x1b[0m', '✓');
                console.log('\x1b[32m%s\x1b[0m', `💰 Claimed ${statusInfo.currentEarnedPoints} points`);
                await delay(1000);
              } catch (error) {
                console.log('\x1b[31m%s\x1b[0m', '❌');
                console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to stop node: ${error.message}`);
              }
            }
            process.stdout.write('\x1b[90m[+]\x1b[0m Starting node... ');
            await axios.post('https://dashboard.synthelix.io/api/node/start', null, {
              ...session.axiosConfig,
              headers: { ...session.commonHeaders, 'Cookie': session.cookies }
            });
            console.log('\x1b[32m%s\x1b[0m', '✓');
            await claimDailyRewards(address, session.cookies, session.commonHeaders, session.axiosConfig, walletLabel);
            const updatedStatus = await getNodeStatus(session.cookies, session.commonHeaders, session.axiosConfig);
            const updatedPoints = await getPointsInfo(session.cookies, session.commonHeaders, session.axiosConfig);
            walletSessions[address].timeLeft = updatedStatus.timeLeft;
            walletSessions[address].statusInfo = updatedStatus;
            walletSessions[address].pointsInfo = updatedPoints;
          }
        } else {
          console.log('\x1b[33m%s\x1b[0m', `⚠️ Session expired for ${walletLabel}: ${shortAddress}, logging in again...`);
          const result = await startSynthelixNodeForWallet(privateKey, proxy, walletLabel);
          if (result.success) {
            walletSessions[address] = result;
          }
        }
      } catch (error) {
        console.error('\x1b[31m%s\x1b[0m', `❌ Error ${walletLabel}: ${shortAddress}: ${error.message}`);
      }

      if (i < privateKeys.length - 1) await delay(DELAY_BETWEEN_WALLETS);
    }

    console.log('\x1b[36m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log('\x1b[36m%s\x1b[0m', `SUMMARY`);
    console.log(`Total Wallets: ${privateKeys.length}`);
    console.log(`Active Nodes: ${activeWallets}`);
    const nextCheckTime = new Date(Date.now() + CHECK_INTERVAL);
    console.log(`Next Check: ${nextCheckTime.toLocaleString()}`);
    console.log('\x1b[36m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

    await delay(CHECK_INTERVAL);
  }
}

monitorAndRestartNodes();