import { Actor, HttpAgent } from "@dfinity/agent";
import { idlFactory } from "../../../.dfx/ic/canisters/sol_icp_poc_backend/service.did.js";

const host = process.env.DFX_NETWORK === "ic" ? "https://ic0.app" : "http://localhost:4943";
const canisterId = process.env.CANISTER_ID_SOL_ICP_POC_BACKEND;
const agent = new HttpAgent({ host });

if (process.env.DFX_NETWORK !== "ic") {
  agent.fetchRootKey();
}

const actor = Actor.createActor(idlFactory, { agent, canisterId });

// Phantom detection from docs
function getProvider() {
    if ("phantom" in window) {
        const provider = window.phantom?.solana;
        if (provider?.isPhantom) return provider;
    }
    window.open("https://phantom.app/", "_blank");
}

const provider = getProvider();
let solPubkey = null;

document.getElementById("connect").onclick = async () => {
    try {
        const resp = await provider.connect();
        solPubkey = resp.publicKey.toString();
        document.getElementById("pubkey").innerText = `Sol Pubkey: ${solPubkey}`;

        // Get deposit address
        const deposit = await actor.get_deposit_address(solPubkey);
        document.getElementById("deposit").innerText = `Deposit to: ${deposit} (Send ICP here manually)`;

        // Get PID
        const pid = await actor.get_pid(solPubkey);
        document.getElementById("pid").innerText = `ICP PID: ${pid}`;

        // Get balance
        const balanceE8s = await actor.get_balance(solPubkey);
        const balanceICP = (Number(balanceE8s) / 1e8).toFixed(8);
        document.getElementById("balance").innerText = `Balance: ${balanceICP} ICP`;
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    }
};

document.getElementById("send").onclick = async () => {
    if (!solPubkey) return alert("Connect first");

    const to = document.getElementById("to").value;
    const amountICP = document.getElementById("amount").value;
    if (isNaN(parseFloat(amountICP)) || parseFloat(amountICP) < 0) {
        return alert("Invalid amount");
    }
    const amount = BigInt(Math.round(parseFloat(amountICP) * 1e8));
    const nonce = await actor.get_nonce(solPubkey);

    // Message from docs pattern
    const message = `transfer to ${to} amount ${amount} nonce ${nonce}`;
    const encodedMessage = new TextEncoder().encode(message);

    const button = document.getElementById("send");
    button.disabled = true;
    button.innerText = 'Sending...';

    try {
        const signed = await provider.signMessage(encodedMessage, "utf8");
        const signature = signed.signature; // Uint8Array

        const result = await actor.transfer(to, amount, solPubkey, Array.from(signature), nonce);
        document.getElementById("status").innerText = result;

        // Refresh balance
        const balanceE8s = await actor.get_balance(solPubkey);
        const balanceICP = (Number(balanceE8s) / 1e8).toFixed(8);
        document.getElementById("balance").innerText = `Balance: ${balanceICP} ICP`;

        // Clear inputs only on success
        if (result.startsWith("Transfer successful")) {
            document.getElementById("to").value = '';
            document.getElementById("amount").value = '';
        }
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    } finally {
        button.disabled = false;
        button.innerText = 'Send ICP';
    }
};

document.getElementById("logout").onclick = async () => {
    try {
        await provider.disconnect();
        solPubkey = null;
        document.getElementById("pubkey").innerText = '';
        document.getElementById("pid").innerText = '';
        document.getElementById("deposit").innerText = '';
        document.getElementById("balance").innerText = '';
        document.getElementById("status").innerText = 'Disconnected. To prevent auto-reconnect, revoke access in Phantom settings (Settings > Connected Apps > Revoke this app) or lock your wallet.';
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    }
};