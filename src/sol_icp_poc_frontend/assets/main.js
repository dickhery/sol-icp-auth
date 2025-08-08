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

const serviceFeeICP = 0.0001;
const serviceFeeSolICP = 0.0002;
const networkFeeICP = 0.0002; // For two ledger transfers
const solanaFeeApprox = 0.000005; // Approximate Solana tx fee
const serviceFeeE8s = BigInt(Math.round(serviceFeeICP * 1e8));
const serviceFeeSolE8s = BigInt(Math.round(serviceFeeSolICP * 1e8));

document.getElementById("connect").onclick = async () => {
    try {
        const resp = await provider.connect();
        solPubkey = resp.publicKey.toString();
        document.getElementById("pubkey").innerText = `Sol Pubkey: ${solPubkey}`;

        // Get ICP deposit address
        const deposit = await actor.get_deposit_address(solPubkey);
        document.getElementById("deposit").innerText = `ICP Deposit to: ${deposit} (Send ICP here manually)`;

        // Get SOL deposit address
        const sol_deposit = await actor.get_sol_deposit_address(solPubkey);
        document.getElementById("sol_deposit").innerText = `SOL Deposit to: ${sol_deposit} (Send SOL here manually)`;

        // Get PID
        const pid = await actor.get_pid(solPubkey);
        document.getElementById("pid").innerText = `ICP PID: ${pid}`;

        // Get ICP balance
        const balanceE8s = await actor.get_balance(solPubkey);
        const balanceICP = (Number(balanceE8s) / 1e8).toFixed(8);
        document.getElementById("balance").innerText = `ICP Balance: ${balanceICP} ICP`;

        // Get SOL balance (initial)
        const solBalanceLam = await actor.get_sol_balance(solPubkey);
        const solBalance = (Number(solBalanceLam) / 1e9).toFixed(9);
        document.getElementById("sol_balance").innerText = `SOL Balance: ${solBalance} SOL`;
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    }
};

document.getElementById("get_sol").onclick = async () => {
    if (!solPubkey) return alert("Connect first");
    try {
        const solBalanceLam = await actor.get_sol_balance(solPubkey);
        const solBalance = (Number(solBalanceLam) / 1e9).toFixed(9);
        document.getElementById("sol_balance").innerText = `SOL Balance: ${solBalance} SOL`;
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

    const amountICPNum = parseFloat(amountICP);
    const totalICP = amountICPNum + serviceFeeICP + networkFeeICP;
    const confirmMsg = `Confirm transaction:\nTo: ${to}\nAmount: ${amountICP} ICP\nNetwork fee: ${networkFeeICP} ICP (includes ledger fees for transaction processing)\nService fee: ${serviceFeeICP} ICP\nTotal deduction from your balance: ${totalICP.toFixed(8)} ICP`;
    if (!window.confirm(confirmMsg)) {
        return;
    }

    // Message from docs pattern
    const message = `transfer to ${to} amount ${amount} nonce ${nonce} service_fee ${serviceFeeE8s}`;
    const encodedMessage = new TextEncoder().encode(message);

    const button = document.getElementById("send");
    button.disabled = true;
    button.innerText = 'Sending...';

    try {
        const signed = await provider.signMessage(encodedMessage, "utf8");
        const signature = signed.signature; // Uint8Array

        const result = await actor.transfer(to, amount, solPubkey, Array.from(signature), nonce);
        document.getElementById("status").innerText = result;

        // Refresh ICP balance
        const balanceE8s = await actor.get_balance(solPubkey);
        const balanceICP = (Number(balanceE8s) / 1e8).toFixed(8);
        document.getElementById("balance").innerText = `ICP Balance: ${balanceICP} ICP`;

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
    const confirmMsg = `Confirm SOL transaction:\nTo: ${to_sol}\nAmount: ${amountSOL} SOL\nSolana fee: ~${solanaFeeApprox} SOL\nService fee: ${serviceFeeSolICP} ICP\nTotal SOL deduction: ${totalSOL.toFixed(9)} SOL\nTotal ICP deduction: ${serviceFeeSolICP} ICP`;
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
        const signature = signed.signature; // Uint8Array

        const result = await actor.transfer_sol(to_sol, amountLam, solPubkey, Array.from(signature), nonce);
        document.getElementById("status").innerText = result;

        // Refresh SOL balance
        const solBalanceLam = await actor.get_sol_balance(solPubkey);
        const solBalance = (Number(solBalanceLam) / 1e9).toFixed(9);
        document.getElementById("sol_balance").innerText = `SOL Balance: ${solBalance} SOL`;

        // Clear inputs only on success
        if (result.startsWith("Transfer successful")) {
            document.getElementById("to_sol").value = '';
            document.getElementById("amount_sol").value = '';
        }
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    } finally {
        button.disabled = false;
        button.innerText = 'Send SOL';
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
        document.getElementById("sol_deposit").innerText = '';
        document.getElementById("sol_balance").innerText = '';
        document.getElementById("status").innerText = 'Disconnected. To prevent auto-reconnect, revoke access in Phantom settings (Settings > Connected Apps > Revoke this app) or lock your wallet.';
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    }
};