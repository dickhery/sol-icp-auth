import { Actor, HttpAgent } from "@dfinity/agent";
import { idlFactory } from "./sol_icp_poc_backend.did.js"; // Generate this via dfx build
// Note: Run `dfx build` to generate sol_icp_poc_backend.did.js in declarations/

const canisterId = "uxrrr-q7777-77774-qaaaq-cai"; // Replace with dfx canister id sol_icp_poc_backend after deploy
const agent = new HttpAgent({ host: "http://localhost:4943" }); // For local; change to https://icp0.io for mainnet
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

        // Get balance
        const balance = await actor.get_balance(solPubkey);
        document.getElementById("balance").innerText = `Balance: ${balance} e8s`;
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    }
};

document.getElementById("send").onclick = async () => {
    if (!solPubkey) return alert("Connect first");

    const to = document.getElementById("to").value;
    const amount = BigInt(document.getElementById("amount").value);
    const nonce = await actor.get_nonce(solPubkey);

    // Message from docs pattern
    const message = `transfer to ${to} amount ${amount} nonce ${nonce}`;
    const encodedMessage = new TextEncoder().encode(message);

    try {
        const signed = await provider.signMessage(encodedMessage, "utf8");
        const signature = signed.signature; // Uint8Array

        const result = await actor.transfer(to, amount, solPubkey, Array.from(signature), nonce);
        document.getElementById("status").innerText = result;

        // Refresh balance
        const balance = await actor.get_balance(solPubkey);
        document.getElementById("balance").innerText = `Balance: ${balance} e8s`;
    } catch (err) {
        document.getElementById("status").innerText = `Error: ${err.message}`;
    }
};