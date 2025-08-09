import { Actor, HttpAgent } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import idlFactory from "./sol_icp_poc_backend.idl.js";

const host = process.env.DFX_NETWORK === "ic" ? "https://ic0.app" : "http://localhost:4943";
const canisterId = process.env.CANISTER_ID_SOL_ICP_POC_BACKEND;

let authClient = null;
let identity = null;
let agent = null;
let actor = null;

function getProvider() {
  if ("phantom" in window) {
    const provider = window.phantom?.solana;
    if (provider?.isPhantom) return provider;
  }
  window.open("https://phantom.app/", "_blank");
}
const provider = getProvider();
let solPubkey = null;

const serviceFeeICP = 0.0001;         // ICP fee for ICP transfers
const serviceFeeSolICP = 0.0002;      // ICP fee for SOL ops
const icpLedgerFee = 0.0001;          // ICP ledger fee to move service fee
const networkFeeICP = 0.0002;         // for two ledger ops in ICP send flow
const solanaFeeApprox = 0.000005;     // SOL fee approx
const serviceFeeE8s = BigInt(Math.round(serviceFeeICP * 1e8));
const serviceFeeSolE8s = BigInt(Math.round(serviceFeeSolICP * 1e8));

async function makeAgentAndActor() {
  agent = new HttpAgent({ host, identity: identity ?? undefined });
  if (process.env.DFX_NETWORK !== "ic") {
    await agent.fetchRootKey();
  }
  actor = Actor.createActor(idlFactory, { agent, canisterId });
}

function uiSet(textId, value) {
  document.getElementById(textId).innerText = value;
}

async function initAuth() {
  authClient = await AuthClient.create();

  if (await authClient.isAuthenticated()) {
    identity = authClient.getIdentity();
    await makeAgentAndActor();

    const prin = await actor.whoami();
    uiSet("ii_status", `Signed in as: ${prin}`);
  } else {
    identity = null;
    await makeAgentAndActor();
    uiSet("ii_status", "Not signed in");
  }
}

function iiProviderForNetwork() {
  return {
    identityProvider: "https://identity.ic0.app",
    // If you serve from a raw domain, provide a derivationOrigin and host /.well-known/ii-alternative-origins as per spec.
  };
}

/* --------------------------- II login/logout --------------------------- */

document.getElementById("ii_login").onclick = async () => {
  if (!authClient) await initAuth();

  const opts = iiProviderForNetwork();
  authClient.login({
    ...opts,
    maxTimeToLive: BigInt(7) * BigInt(24*60*60*1_000_000_000), // 7 days
    onSuccess: async () => {
      identity = authClient.getIdentity();
      await makeAgentAndActor();
      try {
        const prin = await actor.whoami();
        uiSet("ii_status", `Signed in as: ${prin}`);
      } catch (e) {
        uiSet("ii_status", `Signed in (whoami failed): ${e?.message ?? e}`);
      }
    },
    onError: (err) => {
      uiSet("ii_status", `Login failed: ${err?.message ?? err}`);
    }
  });
};

document.getElementById("ii_logout").onclick = async () => {
  if (!authClient) await initAuth();
  await authClient.logout();
  identity = null;
  await makeAgentAndActor();
  uiSet("ii_status", "Not signed in");
};

/* --------------------------- Phantom connect/logout --------------------------- */

document.getElementById("connect").onclick = async () => {
  try {
    const resp = await provider.connect();
    solPubkey = resp.publicKey.toString();
    uiSet("pubkey", `Sol Pubkey: ${solPubkey} (Solana Mainnet)`);

    // Require II for canister access now
    const prin = await actor.whoami();
    uiSet("ii_status", `Signed in as: ${prin}`);

    // Try guarded calls; if not linked yet, show hints instead of throwing
    try {
      const deposit = await actor.get_deposit_address(solPubkey);
      uiSet("deposit", `ICP Deposit to: ${deposit} (Send ICP here manually)`);
    } catch {
      uiSet("deposit", `Link your Phantom wallet to II to reveal ICP deposit address`);
    }

    try {
      const solDeposit = await actor.get_sol_deposit_address(solPubkey);
      uiSet("sol_deposit", `SOL Deposit to: ${solDeposit} (Mainnet; send SOL here manually)`);
    } catch {
      uiSet("sol_deposit", `Link your Phantom wallet to II to reveal SOL deposit address`);
    }

    try {
      const pid = await actor.get_pid(solPubkey);
      uiSet("pid", `ICP PID (derived): ${pid}`);
    } catch {}

    try {
      const balanceE8s = await actor.get_balance(solPubkey);
      const balanceICP = (Number(balanceE8s) / 1e8).toFixed(8);
      uiSet("balance", `ICP Balance: ${balanceICP} ICP`);
    } catch {
      uiSet("balance", `Link first to view ICP balance`);
    }

    try {
      const solBalanceLam = await actor.get_sol_balance(solPubkey);
      const solBalance = (Number(solBalanceLam) / 1e9).toFixed(9);
      uiSet("sol_balance", `SOL Balance: ${solBalance} SOL`);
    } catch {
      uiSet("sol_balance", `Link first to view SOL balance`);
    }
  } catch (err) {
    uiSet("status", `Error: ${err.message}`);
  }
};

document.getElementById("logout").onclick = async () => {
  try {
    await provider.disconnect();
    solPubkey = null;
    ["pubkey","pid","deposit","balance","sol_deposit","sol_balance"].forEach(id => uiSet(id, ""));
    uiSet("status", "Disconnected Phantom. To prevent auto-reconnect, revoke in Phantom settings.");
  } catch (err) {
    uiSet("status", `Error: ${err.message}`);
  }
};

/* --------------------------- Link wallet to II --------------------------- */

document.getElementById("link_wallet").onclick = async () => {
  if (!solPubkey) return alert("Connect Phantom first");
  try {
    const prin = await actor.whoami();
    const message = `link ${prin}`;
    const encoded = new TextEncoder().encode(message);
    const signed = await provider.signMessage(encoded, "utf8");
    const signature = signed.signature;

    const res = await actor.link_sol_pubkey(solPubkey, Array.from(signature));
    uiSet("status", res);
  } catch (err) {
    uiSet("status", `Link error: ${err.message}`);
  }
};

/* --------------------------- ICP send --------------------------- */

document.getElementById("send").onclick = async () => {
  if (!solPubkey) return alert("Connect Phantom first");

  const to = document.getElementById("to").value;
  const amountICP = document.getElementById("amount").value;
  if (isNaN(parseFloat(amountICP)) || parseFloat(amountICP) < 0) {
    return alert("Invalid amount");
  }
  const amount = BigInt(Math.round(parseFloat(amountICP) * 1e8));
  const nonce = await actor.get_nonce(solPubkey);

  const amountICPNum = parseFloat(amountICP);
  const totalICP = amountICPNum + serviceFeeICP + networkFeeICP;
  const confirmMsg = `Confirm transaction:
To: ${to}
Amount: ${amountICP} ICP
Network fee: ${networkFeeICP} ICP
Service fee: ${serviceFeeICP} ICP
Total deduction: ${totalICP.toFixed(8)} ICP`;
  if (!window.confirm(confirmMsg)) {
    return;
  }

  const message = `transfer to ${to} amount ${amount} nonce ${nonce} service_fee ${serviceFeeE8s}`;
  const encodedMessage = new TextEncoder().encode(message);

  const button = document.getElementById("send");
  button.disabled = true;
  button.innerText = 'Sending...';

  try {
    const signed = await provider.signMessage(encodedMessage, "utf8");
    const signature = signed.signature;

    const result = await actor.transfer(to, amount, solPubkey, Array.from(signature), nonce);
    uiSet("status", result);

    const balanceE8s = await actor.get_balance(solPubkey);
    const balanceICP = (Number(balanceE8s) / 1e8).toFixed(8);
    uiSet("balance", `ICP Balance: ${balanceICP} ICP`);

    if (result.startsWith("Transfer successful")) {
      document.getElementById("to").value = '';
      document.getElementById("amount").value = '';
    }
  } catch (err) {
    uiSet("status", `Error: ${err.message}`);
  } finally {
    button.disabled = false;
    button.innerText = 'Send ICP';
  }
};

/* --------------------------- SOL send --------------------------- */

document.getElementById("get_sol").onclick = async () => {
  if (!solPubkey) return alert("Connect first");
  try {
    const solBalanceLam = await actor.get_sol_balance(solPubkey);
    const solBalance = (Number(solBalanceLam) / 1e9).toFixed(9);
    uiSet("sol_balance", `SOL Balance: ${solBalance} SOL`);
  } catch (err) {
    uiSet("status", `Error: ${err.message}`);
  }
};

document.getElementById("send_sol").onclick = async () => {
  if (!solPubkey) return alert("Connect first");

  const to_sol = document.getElementById("to_sol").value;
  const amountSOL = document.getElementById("amount_sol").value;
  if (isNaN(parseFloat(amountSOL)) || parseFloat(amountSOL) < 0) {
    return alert("Invalid amount");
  }
  const amountLam = BigInt(Math.round(parseFloat(amountSOL) * 1e9));
  const nonce = await actor.get_nonce(solPubkey);

  const amountSOLNum = parseFloat(amountSOL);
  const totalSOL = amountSOLNum + solanaFeeApprox;
  const totalIcpForSol = serviceFeeSolICP + icpLedgerFee;
  const confirmMsg = `Confirm SOL transaction:
To: ${to_sol}
Amount: ${amountSOL} SOL
Solana fee: ~${solanaFeeApprox} SOL
ICP ledger fee: ${icpLedgerFee} ICP
Service fee: ${serviceFeeSolICP} ICP
Total SOL deduction: ${totalSOL.toFixed(9)} SOL
Total ICP deduction: ${totalIcpForSol.toFixed(4)} ICP`;
  if (!window.confirm(confirmMsg)) {
    return;
  }

  const message = `transfer_sol to ${to_sol} amount ${amountLam} nonce ${nonce} service_fee ${serviceFeeSolE8s}`;
  const encodedMessage = new TextEncoder().encode(message);

  const button = document.getElementById("send_sol");
  button.disabled = true;
  button.innerText = 'Sending...';

  try {
    const signed = await provider.signMessage(encodedMessage, "utf8");
    const signature = signed.signature;

    const result = await actor.transfer_sol(to_sol, amountLam, solPubkey, Array.from(signature), nonce);
    uiSet("status", result);

    const solBalanceLam = await actor.get_sol_balance(solPubkey);
    const solBalance = (Number(solBalanceLam) / 1e9).toFixed(9);
    uiSet("sol_balance", `SOL Balance: ${solBalance} SOL`);

    if (result.startsWith("Transfer successful")) {
      document.getElementById("to_sol").value = '';
      document.getElementById("amount_sol").value = '';
    }
  } catch (err) {
    uiSet("status", `Error: ${err.message}`);
  } finally {
    button.disabled = false;
    button.innerText = 'Send SOL';
  }
};

/* --------------------------- boot --------------------------- */
await initAuth();
