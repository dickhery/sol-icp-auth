import { Actor, HttpAgent } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import idlFactory from "./sol_icp_poc_backend.idl.js";

const host = process.env.DFX_NETWORK === "ic" ? "https://ic0.app" : "http://localhost:4943";
const canisterId = process.env.CANISTER_ID_SOL_ICP_POC_BACKEND;

let authClient = null;
let identity = null;
let agent = null;
let actor = null;

let authMode = null; // "ii" | "phantom"
let solPubkey = null;

// ---- UI helpers ----
function setVisible(id, visible) {
  document.getElementById(id).style.display = visible ? "block" : "none";
}
function uiSet(id, value) {
  document.getElementById(id).innerText = value;
}
function alertSet(cls, msg) {
  const el = document.getElementById("alerts");
  el.className = cls;
  el.textContent = msg || "";
}
const showOk = (m) => alertSet("ok", m);
const showWarn = (m) => alertSet("warn", m);
const showErr = (m) => alertSet("err", m);
const showMuted = (m) => alertSet("muted", m);

function normalizeAgentError(e) {
  const s = (e?.message || String(e || "")).trim();
  if (/Request timed out after 300000 msec/i.test(s)) {
    return "Request timed out. This may be due to network delays or consensus issues. Retry in a few seconds, or check balances later as the TX may still complete.";
  }
  if (/processing/i.test(s) && /Request ID:/i.test(s)) {
    return "The network is processing the call. Refresh balances shortly.";
  }
  if (/inconsistent/i.test(s) || /consensus/i.test(s)) {
    return "Network variance prevented consensus. Retry the operation.";
  }
  if (/blockhash/i.test(s)) {
    return "Blockhash retrieval failed; network may be busy. Retry.";
  }
  return s;
}

function friendlyTry(fn, onErr) {
  return fn().catch((e) => {
    const msg = normalizeAgentError(e);
    if (onErr) onErr(msg, e);
    else showErr(msg);
    throw e; // keep behavior for upstream catch/finally
  });
}

async function makeAgentAndActor() {
  agent = new HttpAgent({ host, identity: identity ?? undefined });
  if (process.env.DFX_NETWORK !== "ic") {
    await agent.fetchRootKey();
  }
  actor = Actor.createActor(idlFactory, { agent, canisterId });
}

async function initAuthIfNeeded() {
  if (!authClient) authClient = await AuthClient.create();
}

// ---- Phantom provider ----
function getProvider() {
  if ("phantom" in window) {
    const provider = window.phantom?.solana;
    if (provider?.isPhantom) return provider;
  }
  window.open("https://phantom.app/", "_blank");
}
const provider = getProvider();

// ---- fees & constants ----
const serviceFeeICP = 0.0001;         // ICP fee for ICP transfers
const serviceFeeSolICP = 0.0002;      // ICP fee for SOL ops
const icpLedgerFee = 0.0001;          // ICP ledger fee to move service fee
const networkFeeICP = 0.0002;         // two ledger ops in ICP send flow
const solanaFeeApprox = 0.000005;     // SOL fee approx
const serviceFeeE8s = BigInt(Math.round(serviceFeeICP * 1e8));
const serviceFeeSolE8s = BigInt(Math.round(serviceFeeSolICP * 1e8));

// ---- Throttle state for refreshes ----
let lastSolRefreshMs = 0;
let solRefreshInFlight = false;
let lastIcpRefreshMs = 0;
let icpRefreshInFlight = false;
const COOLDOWN_MS = 10_000;

// Shared refresh that respects auth mode + cooldowns
async function refreshSolBalance(force = false) {
  const now = Date.now();
  if (!force && (now - lastSolRefreshMs) < COOLDOWN_MS) {
    const wait = Math.ceil((COOLDOWN_MS - (now - lastSolRefreshMs)) / 1000);
    showWarn(`Please wait ~${wait}s before refreshing SOL again.`);
    return;
  }
  if (solRefreshInFlight) {
    showMuted("Refreshing SOL…");
    return;
  }
  solRefreshInFlight = true;
  const button = document.getElementById("get_sol");
  if (button) { button.disabled = true; }

  try {
    if (authMode === "ii") {
      const lam = await friendlyTry(() => actor.get_sol_balance_ii(), (m) => showWarn(m));
      uiSet("sol_balance", `SOL Balance: ${(Number(lam)/1e9).toFixed(9)} SOL`);
      showMuted("SOL balance updated.");
    } else if (authMode === "phantom") {
      if (!solPubkey) return showWarn("Connect Phantom first");
      const lam = await friendlyTry(() => actor.get_sol_balance(solPubkey), (m) => showWarn(m));
      uiSet("sol_balance", `SOL Balance: ${(Number(lam)/1e9).toFixed(9)} SOL`);
      showMuted("SOL balance updated.");
    } else {
      showWarn("Pick an auth mode to refresh SOL.");
    }
    lastSolRefreshMs = Date.now();
  } finally {
    solRefreshInFlight = false;
    if (button) { button.disabled = false; }
  }
}

async function refreshIcpBalance(force = false) {
  const now = Date.now();
  if (!force && (now - lastIcpRefreshMs) < COOLDOWN_MS) {
    const wait = Math.ceil((COOLDOWN_MS - (now - lastIcpRefreshMs)) / 1000);
    showWarn(`Please wait ~${wait}s before refreshing ICP again.`);
    return;
  }
  if (icpRefreshInFlight) {
    showMuted("Refreshing ICP…");
    return;
  }
  icpRefreshInFlight = true;
  const button = document.getElementById("refresh_icp");
  if (button) { button.disabled = true; }

  try {
    if (authMode === "ii") {
      const e8s = await friendlyTry(() => actor.get_balance_ii(), (m) => showWarn(m));
      uiSet("balance", `ICP Balance: ${(Number(e8s)/1e8).toFixed(8)} ICP`);
      showMuted("ICP balance updated.");
    } else if (authMode === "phantom") {
      if (!solPubkey) return showWarn("Connect Phantom first");
      const e8s = await friendlyTry(() => actor.get_balance(solPubkey), (m) => showWarn(m));
      uiSet("balance", `ICP Balance: ${(Number(e8s)/1e8).toFixed(8)} ICP`);
      showMuted("ICP balance updated.");
    } else {
      showWarn("Pick an auth mode to refresh ICP.");
    }
    lastIcpRefreshMs = Date.now();
  } finally {
    icpRefreshInFlight = false;
    if (button) { button.disabled = false; }
  }
}

async function refreshBothBalances(force = false) {
  await Promise.allSettled([
    refreshIcpBalance(force),
    refreshSolBalance(force),
  ]);
}

// ---- Auth mode switching ----
function enterIiUi() {
  setVisible("ii_block", true);
  setVisible("phantom_block", false);
  uiSet("mode_status", "Mode: Internet Identity");
  alertSet("", "");
}
function enterPhantomUi() {
  setVisible("phantom_block", true);
  setVisible("ii_block", false);
  uiSet("mode_status", "Mode: Phantom");
  alertSet("", "");
}

document.getElementById("mode_ii").onclick = async () => {
  if (authMode === "phantom") {
    try { await provider.disconnect(); } catch {}
    solPubkey = null;
    ["pubkey","sol_deposit","sol_balance"].forEach(id => uiSet(id, ""));
  }
  authMode = "ii";
  await initAuthIfNeeded();
  await makeAgentAndActor();
  enterIiUi();
};

document.getElementById("mode_phantom").onclick = async () => {
  if (authMode === "ii") {
    if (!authClient) await initAuthIfNeeded();
    try { await authClient.logout(); } catch {}
    identity = null;
  }
  authMode = "phantom";
  await makeAgentAndActor();
  enterPhantomUi();
};

// ---- II login/logout ----
document.getElementById("ii_login").onclick = async () => {
  if (authMode !== "ii") return alert("Switch to Internet Identity mode first");
  await initAuthIfNeeded();
  const opts = { identityProvider: "https://identity.ic0.app" };
  authClient.login({
    ...opts,
    maxTimeToLive: BigInt(7) * BigInt(24*60*60*1_000_000_000),
    onSuccess: async () => {
      identity = authClient.getIdentity();
      await makeAgentAndActor();
      try {
        const prin = await actor.whoami();
        uiSet("ii_status", `Signed in as: ${prin}`);

        // hydrate II-only addresses/balances
        const dep = await friendlyTry(() => actor.get_deposit_address_ii(), (m) => showWarn(m));
        uiSet("deposit", `ICP Deposit to: ${dep}`);
        const solDep = await friendlyTry(() => actor.get_sol_deposit_address_ii(), (m) => showWarn(m));
        uiSet("sol_deposit", `SOL Deposit to: ${solDep}`);
        uiSet("pid", `ICP Principal: ${prin}`);

        await refreshBothBalances(true); // no throttle on first load
        showOk("Logged in with Internet Identity.");
      } catch (e) {
        uiSet("ii_status", `Signed in (fetch error).`);
        showWarn(normalizeAgentError(e));
      }
    },
    onError: (err) => {
      showErr(`II login failed: ${normalizeAgentError(err)}`);
    }
  });
};

document.getElementById("ii_logout").onclick = async () => {
  await initAuthIfNeeded();
  await authClient.logout();
  identity = null;
  await makeAgentAndActor();
  uiSet("ii_status", "Not signed in");
  uiSet("pid", "");
  showMuted("Logged out of Internet Identity.");
};

// ---- Phantom connect/logout ----
document.getElementById("connect").onclick = async () => {
  if (authMode !== "phantom") return alert("Switch to Phantom mode first");
  try {
    const resp = await provider.connect();
    solPubkey = resp.publicKey.toString();
    uiSet("pubkey", `Sol Pubkey: ${solPubkey} (Solana Mainnet)`);

    // Fetch deposit addresses and balances (no II required)
    const deposit = await friendlyTry(() => actor.get_deposit_address(solPubkey), (m) => showWarn(m));
    uiSet("deposit", `ICP Deposit to: ${deposit} (Send ICP here)`);
    const solDeposit = await friendlyTry(() => actor.get_sol_deposit_address(solPubkey), (m) => showWarn(m));
    uiSet("sol_deposit", `SOL Deposit to: ${solDeposit} (Mainnet; send SOL here)`);

    await refreshBothBalances(true); // immediate, no throttle
    showOk("Connected to Phantom.");
  } catch (err) {
    showErr(`Phantom connect error: ${normalizeAgentError(err)}`);
  }
};

document.getElementById("logout").onclick = async () => {
  try { await provider.disconnect(); } catch {}
  solPubkey = null;
  ["pubkey","pid","deposit","balance","sol_deposit","sol_balance"].forEach(id => uiSet(id, ""));
  showMuted("Disconnected Phantom. To prevent auto‑reconnect, revoke in Phantom settings.");
};

// ---- Link wallet to II (optional) ----
document.getElementById("link_wallet").onclick = async () => {
  if (!solPubkey) return alert("Connect Phantom first");
  try {
    if (!authClient) await initAuthIfNeeded();
    if (!(await authClient.isAuthenticated())) return alert("Login with Internet Identity (II mode) to link");
    const prin = await actor.whoami();
    const message = `link ${prin}`;
    const encoded = new TextEncoder().encode(message);
    const signed = await provider.signMessage(encoded, "utf8");
    const signature = signed.signature;

    const res = await friendlyTry(() => actor.link_sol_pubkey(solPubkey, Array.from(signature)));
    showOk(res);
  } catch (err) {
    showErr(`Link error: ${normalizeAgentError(err)}`);
  }
};

// ---- ICP send ----
document.getElementById("send").onclick = async () => {
  const to = document.getElementById("to").value;
  const amountICP = document.getElementById("amount").value;
  if (isNaN(parseFloat(amountICP)) || parseFloat(amountICP) < 0) {
    return alert("Invalid amount");
  }
  const amount = BigInt(Math.round(parseFloat(amountICP) * 1e8));

  if (authMode === "ii") {
    const totalICP = parseFloat(amountICP) + networkFeeICP + serviceFeeICP;
    const confirmMsg = `Confirm transaction (II mode):
To: ${to}
Amount: ${amountICP} ICP
Network fee: ${networkFeeICP} ICP
Service fee: ${serviceFeeICP} ICP
Total deduction: ${totalICP.toFixed(8)} ICP`;
    if (!window.confirm(confirmMsg)) return;

    const button = document.getElementById("send");
    button.disabled = true; button.innerText = 'Processing... (may take 30s)';

    try {
      const result = await friendlyTry(() => actor.transfer_ii(to, amount), (m) => showWarn(m));
      uiSet("status", result);
      await refreshBothBalances(true);
      if (result.startsWith("Transfer successful")) {
        document.getElementById("to").value = '';
        document.getElementById("amount").value = '';
        showOk("ICP transfer complete. Balances updated.");
      } else {
        showWarn(result);
      }
    } catch (err) {
      showErr(`ICP send error: ${normalizeAgentError(err)}`);
    } finally {
      button.disabled = false; button.innerText = 'Send ICP';
    }
    return;
  }

  if (authMode === "phantom") {
    if (!solPubkey) return alert("Connect Phantom first");
    const nonce = await actor.get_nonce(solPubkey);

    const amountICPNum = parseFloat(amountICP);
    const totalICP = amountICPNum + networkFeeICP + serviceFeeICP;
    const confirmMsg = `Confirm transaction (Phantom mode):
To: ${to}
Amount: ${amountICP} ICP
Network fee: ${networkFeeICP} ICP
Service fee: ${serviceFeeICP} ICP
Total deduction: ${totalICP.toFixed(8)} ICP`;
    if (!window.confirm(confirmMsg)) return;

    const message = `transfer to ${to} amount ${amount} nonce ${nonce} service_fee ${serviceFeeE8s}`;
    const encodedMessage = new TextEncoder().encode(message);

    const button = document.getElementById("send");
    button.disabled = true; button.innerText = 'Processing... (may take 30s)';

    try {
      const signed = await provider.signMessage(encodedMessage, "utf8");
      const signature = signed.signature;

      const result = await friendlyTry(() => actor.transfer(to, amount, solPubkey, Array.from(signature), nonce), (m) => showWarn(m));
      uiSet("status", result);
      await refreshBothBalances(true);

      if (result.startsWith("Transfer successful")) {
        document.getElementById("to").value = '';
        document.getElementById("amount").value = '';
        showOk("ICP transfer complete. Balances updated.");
      } else {
        showWarn(result);
      }
    } catch (err) {
      showErr(`ICP send error: ${normalizeAgentError(err)}`);
    } finally {
      button.disabled = false;
      button.innerText = 'Send ICP';
    }
  }
};

// ---- SOL read/send ----
document.getElementById("get_sol").onclick = async () => {
  await refreshSolBalance(false); // throttled
};

document.getElementById("refresh_icp").onclick = async () => {
  await refreshIcpBalance(false); // throttled
};

document.getElementById("send_sol").onclick = async () => {
  const to_sol = document.getElementById("to_sol").value;
  const amountSOL = document.getElementById("amount_sol").value;
  if (isNaN(parseFloat(amountSOL)) || parseFloat(amountSOL) < 0) {
    return alert("Invalid amount");
  }
  const amountLam = BigInt(Math.round(parseFloat(amountSOL) * 1e9));

  if (authMode === "ii") {
    const totalSOL = parseFloat(amountSOL) + solanaFeeApprox;
    const totalIcpForSol = serviceFeeSolICP + icpLedgerFee;
    const confirmMsg = `Confirm SOL transaction (II mode):
To: ${to_sol}
Amount: ${amountSOL} SOL
Solana fee: ~${solanaFeeApprox} SOL
ICP ledger fee: ${icpLedgerFee} ICP
Service fee: ${serviceFeeSolICP} ICP
Total SOL deduction: ${totalSOL.toFixed(9)} SOL
Total ICP deduction: ${totalIcpForSol.toFixed(4)} ICP`;
    if (!window.confirm(confirmMsg)) return;

    const button = document.getElementById("send_sol");
    button.disabled = true; button.innerText = 'Processing... (may take 30s)';

    try {
      const result = await friendlyTry(() => actor.transfer_sol_ii(to_sol, amountLam), (m) => showWarn(m));
      // Extract txid for explorer link
      const txidMatch = result.match(/txid (.+)/);
      const txid = txidMatch ? txidMatch[1] : '';
      uiSet("status", `${result}${txid ? ` View on Solana FM: https://solana.fm/tx/${txid}` : ''}`);
      await refreshBothBalances(true);
      if (result.startsWith("Transfer successful")) {
        document.getElementById("to_sol").value = '';
        document.getElementById("amount_sol").value = '';
        showOk("SOL transfer submitted. Balances updated.");
      } else {
        showWarn(result);
      }
    } catch (err) {
      showErr(`SOL send error: ${normalizeAgentError(err)}`);
    } finally {
      button.disabled = false; button.innerText = 'Send SOL';
    }
    return;
  }

  if (authMode === "phantom") {
    if (!solPubkey) return alert("Connect first");

    const nonce = await actor.get_nonce(solPubkey);

    const amountSOLNum = parseFloat(amountSOL);
    const totalSOL = amountSOLNum + solanaFeeApprox;
    const totalIcpForSol = serviceFeeSolICP + icpLedgerFee;
    const confirmMsg = `Confirm SOL transaction (Phantom mode):
To: ${to_sol}
Amount: ${amountSOL} SOL
Solana fee: ~${solanaFeeApprox} SOL
ICP ledger fee: ${icpLedgerFee} ICP
Service fee: ${serviceFeeSolICP} ICP
Total SOL deduction: ${totalSOL.toFixed(9)} SOL
Total ICP deduction: ${totalIcpForSol.toFixed(4)} ICP`;
    if (!window.confirm(confirmMsg)) return;

    const message = `transfer_sol to ${to_sol} amount ${amountLam} nonce ${nonce} service_fee ${serviceFeeSolE8s}`;
    const encodedMessage = new TextEncoder().encode(message);

    const button = document.getElementById("send_sol");
    button.disabled = true; button.innerText = 'Processing... (may take 30s)';

    try {
      const signed = await provider.signMessage(encodedMessage, "utf8");
      const signature = signed.signature;

      const result = await friendlyTry(() => actor.transfer_sol(to_sol, amountLam, solPubkey, Array.from(signature), nonce), (m) => showWarn(m));
      // Extract txid for explorer link
      const txidMatch = result.match(/txid (.+)/);
      const txid = txidMatch ? txidMatch[1] : '';
      uiSet("status", `${result}${txid ? ` View on Solana FM: https://solana.fm/tx/${txid}` : ''}`);
      await refreshBothBalances(true);

      if (result.startsWith("Transfer successful")) {
        document.getElementById("to_sol").value = '';
        document.getElementById("amount_sol").value = '';
        showOk("SOL transfer submitted. Balances updated.");
      } else {
        showWarn(result);
      }
    } catch (err) {
      showErr(`SOL send error: ${normalizeAgentError(err)}`);
    } finally {
      button.disabled = false;
      button.innerText = 'Send SOL';
    }
  }
};

// ---- Boot ----
await makeAgentAndActor();
uiSet("mode_status", "Pick a mode: Internet Identity or Phantom");
showMuted("Ready.");