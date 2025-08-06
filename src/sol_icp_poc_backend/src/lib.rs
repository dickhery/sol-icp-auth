use ic_cdk::{export_candid, query, update};
use ic_principal::Principal;
use ic_ledger_types::{
    AccountIdentifier, Memo, Subaccount, Timestamp, Tokens, TransferArgs, DEFAULT_FEE,
    MAINNET_LEDGER_CANISTER_ID,
};
use ic_stable_structures::{memory_manager::{MemoryId, MemoryManager, VirtualMemory}, DefaultMemoryImpl, StableBTreeMap};
use sha2::{Digest, Sha224, Sha256};
use std::cell::RefCell;
use bs58;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

type Memory = VirtualMemory<DefaultMemoryImpl>;
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static NONCE_MAP: RefCell<StableBTreeMap<String, u64, Memory>> = RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))));
}

fn derive_subaccount(sol_pubkey: &str) -> Subaccount {
    let mut hasher = Sha256::new();
    hasher.update(sol_pubkey.as_bytes());
    let hash = hasher.finalize();
    let mut subaccount = [0u8; 32];
    subaccount.copy_from_slice(&hash);
    Subaccount(subaccount)
}

fn verify_signature(sol_pubkey: &str, message: &[u8], signature: &[u8]) -> bool {
    let pubkey_bytes = match bs58::decode(sol_pubkey).into_vec() {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return false,
    };
    let pubkey_array: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(arr) => arr,
        _ => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_array) {
        Ok(key) => key,
        _ => return false,
    };
    let sig_array: [u8; 64] = match signature.try_into() {
        Ok(arr) => arr,
        _ => return false,
    };
    let sig = Signature::from_bytes(&sig_array);
    verifying_key.verify(message, &sig).is_ok()
}

#[query]
fn get_deposit_address(sol_pubkey: String) -> String {
    let subaccount = derive_subaccount(&sol_pubkey);
    let account = AccountIdentifier::new(&ic_cdk::id(), &subaccount);
    hex::encode(account.as_ref())
}

#[update]
async fn get_balance(sol_pubkey: String) -> u64 {
    let subaccount = derive_subaccount(&sol_pubkey);
    let account = AccountIdentifier::new(&ic_cdk::id(), &subaccount);
    let args = ic_ledger_types::AccountBalanceArgs { account };
    ic_ledger_types::account_balance(
        MAINNET_LEDGER_CANISTER_ID,
        args,
    ).await.unwrap_or(Tokens::from_e8s(0)).e8s()
}

#[query]
fn get_nonce(sol_pubkey: String) -> u64 {
    NONCE_MAP.with(|map| {
        map.borrow().get(&sol_pubkey).unwrap_or(0)
    })
}

#[update]
async fn transfer(to_hex: String, amount_e8s: u64, sol_pubkey: String, signature: Vec<u8>, nonce: u64) -> String {
    let current_nonce = get_nonce(sol_pubkey.clone());
    if nonce != current_nonce {
        return "Invalid nonce".to_string();
    }

    NONCE_MAP.with(|map| {
        let mut map = map.borrow_mut();
        map.insert(sol_pubkey.clone(), current_nonce + 1);
    });

    let message = format!("transfer to {} amount {} nonce {}", to_hex, amount_e8s, nonce).into_bytes();

    if !verify_signature(&sol_pubkey, &message, &signature) {
        return "Invalid signature".to_string();
    }

    let to_bytes = hex::decode(&to_hex).unwrap_or_default();
    let to = AccountIdentifier::from_slice(&to_bytes).unwrap_or(AccountIdentifier::new(&Principal::anonymous(), &Subaccount([0; 32])));

    let subaccount = derive_subaccount(&sol_pubkey);
    let args = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(amount_e8s),
        fee: DEFAULT_FEE,
        from_subaccount: Some(subaccount),
        to,
        created_at_time: Some(Timestamp { timestamp_nanos: ic_cdk::api::time() }),
    };

    match ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, args).await {
        Ok(Ok(block_index)) => format!("Transfer successful: block {}", block_index),
        _ => "Transfer failed".to_string(),
    }
}

#[query]
fn get_pid(sol_pubkey: String) -> String {
    let pubkey_bytes = match bs58::decode(sol_pubkey).into_vec() {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return "Invalid pubkey".to_string(),
    };
    let mut hasher = Sha224::new();
    hasher.update(&pubkey_bytes);
    let hash = hasher.finalize();
    let mut principal_bytes: Vec<u8> = hash.to_vec();
    principal_bytes.push(0x02); // Ed25519 type byte
    Principal::from_slice(&principal_bytes).to_text()
}

export_candid!();