#[allow(deprecated)]
use ic_cdk::{export_candid, query, update};
use ic_cdk::api::canister_self as canister_id;
use ic_cdk::api::call::call_raw128;
use ic_cdk::management_canister::{
    SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs, SignWithSchnorrArgs, SignWithSchnorrResult,
};
use ic_principal::Principal;
use ic_ledger_types::{
    AccountIdentifier, Memo, Subaccount, Timestamp, Tokens, TransferArgs, TransferError, DEFAULT_FEE,
    MAINNET_LEDGER_CANISTER_ID,
};
use ic_stable_structures::{memory_manager::{MemoryId, MemoryManager, VirtualMemory}, DefaultMemoryImpl, StableBTreeMap};
use sha2::{Digest, Sha256, Sha224};
use std::cell::RefCell;
use bs58;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use lazy_static::lazy_static;
use base64::engine::general_purpose;
use base64::Engine as _;
use candid::{CandidType, Deserialize};

const SOL_RPC_CANISTER: &str = "tghme-zyaaa-aaaar-qarca-cai";

lazy_static! {
    static ref SOL_RPC_PRINCIPAL: Principal = Principal::from_text(SOL_RPC_CANISTER).unwrap();
    static ref SERVICE_ACCOUNT: AccountIdentifier = AccountIdentifier::from_hex(
        "573292a9fdfff9ba7e23bcab9a99ab7db2a96c2e6697cf401a837f1c3a3280ed"
    ).unwrap();
    static ref KEY_ID: SchnorrKeyId = SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: "key_1".to_string()
    };
}

/* ----------------------------- SOL RPC TYPES ----------------------------- */

#[derive(CandidType, Deserialize, Clone)]
pub enum SolanaCluster { Mainnet }

#[derive(CandidType, Deserialize, Clone)]
pub enum RpcSources { Default(SolanaCluster) }

#[derive(CandidType, Deserialize, Clone)]
pub enum ConsensusStrategy { Equality }

#[derive(CandidType, Deserialize, Clone, Default)]
pub struct RpcConfig {
    #[serde(rename = "responseConsensus")]
    pub response_consensus: Option<ConsensusStrategy>,
    #[serde(rename = "responseSizeEstimate")]
    pub response_size_estimate: Option<u64>,
}

pub type Slot = u64;

#[derive(CandidType, Deserialize, Clone)]
pub enum CommitmentLevel {
    #[serde(rename = "finalized")]
    Finalized,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "processed")]
    Processed,
}

/* getBalance */
#[derive(CandidType, Deserialize, Clone)]
pub struct GetBalanceParams {
    pub pubkey: String,
    #[serde(rename = "minContextSlot")]
    pub min_context_slot: Option<Slot>,
    pub commitment: Option<CommitmentLevel>,
}

#[derive(CandidType, Deserialize, Clone)]
pub enum GetBalanceResult {
    Ok(u64),
    Err(String),
}

#[derive(CandidType, Deserialize, Clone)]
pub enum MultiGetBalanceResult {
    Consistent(GetBalanceResult),
    Inconsistent(Vec<(RpcSource, GetBalanceResult)>),
}

#[derive(CandidType, Deserialize, Clone)]
pub enum RpcSource {
    Supported(SupportedProvider),
    Custom(RpcEndpoint),
}
#[derive(CandidType, Deserialize, Clone)]
pub enum SupportedProvider {
    AnkrMainnet, AlchemyDevnet, DrpcMainnet, ChainstackDevnet, AlchemyMainnet,
    HeliusDevnet, AnkrDevnet, DrpcDevnet, ChainstackMainnet, PublicNodeMainnet, HeliusMainnet,
}
#[derive(CandidType, Deserialize, Clone)]
pub struct RpcEndpoint { pub url: String, pub headers: Option<Vec<HttpHeader>> }
#[derive(CandidType, Deserialize, Clone)]
pub struct HttpHeader { pub value: String, pub name: String }

/* getSlot */
#[derive(CandidType, Deserialize, Clone, Default)]
pub struct GetSlotRpcConfig {
    #[serde(rename = "roundingError")]
    pub rounding_error: Option<u64>,
    #[serde(rename = "responseConsensus")]
    pub response_consensus: Option<ConsensusStrategy>,
    #[serde(rename = "responseSizeEstimate")]
    pub response_size_estimate: Option<u64>,
}
#[derive(CandidType, Deserialize, Clone, Default)]
pub struct GetSlotParams {
    #[serde(rename = "minContextSlot")]
    pub min_context_slot: Option<Slot>,
    pub commitment: Option<CommitmentLevel>,
}
#[derive(CandidType, Deserialize, Clone)]
pub enum GetSlotResult {
    Ok(Slot),
    Err(String),
}
#[derive(CandidType, Deserialize, Clone)]
pub enum MultiGetSlotResult {
    Consistent(GetSlotResult),
    Inconsistent(Vec<(RpcSource, GetSlotResult)>),
}

/* getBlock */
#[derive(CandidType, Deserialize, Clone)]
pub enum TransactionDetails {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "signatures")]
    Signatures,
    #[serde(rename = "accounts")]
    Accounts,
}
#[derive(CandidType, Deserialize, Clone)]
pub enum GetBlockParamsCommitmentInner {
    #[serde(rename = "finalized")]
    Finalized,
    #[serde(rename = "confirmed")]
    Confirmed,
}
#[derive(CandidType, Deserialize, Clone)]
pub struct GetBlockParams {
    pub slot: Slot,
    #[serde(rename = "transactionDetails")]
    pub transaction_details: Option<TransactionDetails>,
    pub rewards: Option<bool>,
    pub commitment: Option<GetBlockParamsCommitmentInner>,
    #[serde(rename = "maxSupportedTransactionVersion")]
    pub max_supported_transaction_version: Option<u8>,
}
#[derive(CandidType, Deserialize, Clone)]
pub struct ConfirmedBlock { pub blockhash: String }
#[derive(CandidType, Deserialize, Clone)]
pub enum GetBlockResult {
    Ok(Option<ConfirmedBlock>),
    Err(String),
}
#[derive(CandidType, Deserialize, Clone)]
pub enum MultiGetBlockResult {
    Consistent(GetBlockResult),
    Inconsistent(Vec<(RpcSource, GetBlockResult)>),
}

/* sendTransaction */
#[derive(CandidType, Deserialize, Clone)]
pub enum SendTransactionEncoding {
    #[serde(rename = "base58")] Base58,
    #[serde(rename = "base64")] Base64,
}
#[derive(CandidType, Deserialize, Clone)]
pub struct SendTransactionParams {
    pub transaction: String,
    #[serde(rename = "skipPreflight")]
    pub skip_preflight: Option<bool>,
    pub encoding: Option<SendTransactionEncoding>,
    #[serde(rename = "preflightCommitment")]
    pub preflight_commitment: Option<CommitmentLevel>,
    #[serde(rename = "maxRetries")]
    pub max_retries: Option<u32>,
    #[serde(rename = "minContextSlot")]
    pub min_context_slot: Option<Slot>,
}
#[derive(CandidType, Deserialize, Clone)]
pub enum SendTransactionResult {
    Ok(String), // signature
    Err(String),
}
#[derive(CandidType, Deserialize, Clone)]
pub enum MultiSendTransactionResult {
    Consistent(SendTransactionResult),
    Inconsistent(Vec<(RpcSource, SendTransactionResult)>),
}
/* --------------------------- END SOL RPC TYPES --------------------------- */

type Memory = VirtualMemory<DefaultMemoryImpl>;
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static NONCE_MAP: RefCell<StableBTreeMap<String, u64, Memory>> = RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))));
}

const SERVICE_FEE: u64 = 10_000;     // 0.0001 ICP in e8s for ICP transfers
const SERVICE_FEE_SOL: u64 = 20_000; // 0.0002 ICP in e8s for SOL operations

#[derive(Clone)]
struct CompiledInstrLike {
    prog_idx: u8,
    accts: Vec<u8>,
    data: Vec<u8>,
}

/* ------------------------------ helpers ------------------------------ */

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

async fn get_user_sol_pk(sol_pubkey: &str) -> [u8; 32] {
    let pubkey_bytes = match bs58::decode(sol_pubkey).into_vec() {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => ic_cdk::trap("Invalid Solana pubkey"),
    };
    let derivation_path: Vec<Vec<u8>> = vec![pubkey_bytes.clone()];
    let pk_args = SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path,
        key_id: KEY_ID.clone(),
    };
    let pk_res = ic_cdk::management_canister::schnorr_public_key(&pk_args).await.unwrap();
    let pk = pk_res.public_key;
    if pk.len() != 32 {
        ic_cdk::trap("Invalid public key length");
    }
    pk.try_into().unwrap()
}

fn encode_compact(mut val: u64) -> Vec<u8> {
    let mut res = Vec::new();
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        res.push(byte);
        if val == 0 {
            break;
        }
    }
    res
}

fn serialize_message(header: [u8; 3], accounts: &Vec<[u8; 32]>, blockhash: [u8; 32], instrs: &Vec<CompiledInstrLike>) -> Vec<u8> {
    let mut ser = Vec::new();
    ser.extend(header);
    ser.extend(encode_compact(accounts.len() as u64));
    for acc in accounts {
        ser.extend(*acc);
    }
    ser.extend(blockhash);
    ser.extend(encode_compact(instrs.len() as u64));
    for i in instrs {
        ser.push(i.prog_idx);
        ser.extend(encode_compact(i.accts.len() as u64));
        ser.extend(&i.accts);
        ser.extend(encode_compact(i.data.len() as u64));
        ser.extend(&i.data);
    }
    ser
}

/* ------------------------------ SOL RPC calls ------------------------------ */

async fn sol_get_balance_lamports(pubkey: String) -> Result<u64, String> {
    let rpc_sources = RpcSources::Default(SolanaCluster::Mainnet);
    let rpc_cfg: Option<RpcConfig> = None;

    let params = GetBalanceParams {
        pubkey,
        min_context_slot: None,
        commitment: Some(CommitmentLevel::Finalized),
    };

    let args = candid::encode_args((rpc_sources, rpc_cfg, params)).map_err(|e| e.to_string())?;

    // 2B cycles for a bit more headroom
    let cycles: u128 = 2_000_000_000;
    let raw = call_raw128(*SOL_RPC_PRINCIPAL, "getBalance", args, cycles).await
        .map_err(|err| format!("getBalance call error: {:?}", err))?;

    let (multi,): (MultiGetBalanceResult,) =
        candid::decode_args(&raw).map_err(|e| format!("getBalance decode error: {:?}", e))?;

    match multi {
        MultiGetBalanceResult::Consistent(GetBalanceResult::Ok(lamports)) => Ok(lamports),
        MultiGetBalanceResult::Inconsistent(list) => {
            for (_src, r) in list {
                if let GetBalanceResult::Ok(l) = r { return Ok(l); }
            }
            Err("getBalance inconsistent and no Ok value".into())
        }
        MultiGetBalanceResult::Consistent(GetBalanceResult::Err(e)) => Err(format!("getBalance error: {e}")),
    }
}

async fn sol_get_finalized_slot() -> Result<u64, String> {
    let rpc_sources = RpcSources::Default(SolanaCluster::Mainnet);
    let cfg: Option<GetSlotRpcConfig> = None;
    let params = Some(GetSlotParams { min_context_slot: None, commitment: Some(CommitmentLevel::Finalized) });
    let args = candid::encode_args((rpc_sources, cfg, params)).map_err(|e| e.to_string())?;
    let cycles: u128 = 2_000_000_000;
    let raw = call_raw128(*SOL_RPC_PRINCIPAL, "getSlot", args, cycles).await
        .map_err(|e| format!("getSlot call error: {:?}", e))?;
    let (multi,): (MultiGetSlotResult,) = candid::decode_args(&raw).map_err(|e| format!("getSlot decode error: {:?}", e))?;
    match multi {
        MultiGetSlotResult::Consistent(GetSlotResult::Ok(slot)) => Ok(slot),
        MultiGetSlotResult::Inconsistent(list) => {
            for (_s, r) in list {
                if let GetSlotResult::Ok(slot) = r { return Ok(slot); }
            }
            Err("getSlot inconsistent and no Ok value".into())
        }
        MultiGetSlotResult::Consistent(GetSlotResult::Err(e)) => Err(format!("getSlot error: {e}")),
    }
}

async fn sol_get_blockhash_for_slot(slot: u64) -> Result<String, String> {
    let rpc_sources = RpcSources::Default(SolanaCluster::Mainnet);
    let rpc_cfg: Option<RpcConfig> = None;
    let params = GetBlockParams {
        slot,
        transaction_details: Some(TransactionDetails::None),
        rewards: Some(false),
        commitment: Some(GetBlockParamsCommitmentInner::Finalized),
        max_supported_transaction_version: None,
    };
    let args = candid::encode_args((rpc_sources, rpc_cfg, params)).map_err(|e| e.to_string())?;
    let cycles: u128 = 2_000_000_000;
    let raw = call_raw128(*SOL_RPC_PRINCIPAL, "getBlock", args, cycles).await
        .map_err(|e| format!("getBlock call error: {:?}", e))?;
    let (multi,): (MultiGetBlockResult,) = candid::decode_args(&raw).map_err(|e| format!("getBlock decode error: {:?}", e))?;
    match multi {
        MultiGetBlockResult::Consistent(GetBlockResult::Ok(Some(block))) => Ok(block.blockhash),
        MultiGetBlockResult::Inconsistent(list) => {
            for (_s, r) in list {
                if let GetBlockResult::Ok(Some(block)) = r { return Ok(block.blockhash); }
            }
            Err("getBlock inconsistent and no Ok value".into())
        }
        MultiGetBlockResult::Consistent(GetBlockResult::Ok(None)) =>
            Err("getBlock returned None (no block)".into()),
        MultiGetBlockResult::Consistent(GetBlockResult::Err(e)) =>
            Err(format!("getBlock error: {e}")),
    }
}

async fn sol_send_transaction_b64(tx_b64: String) -> Result<String, String> {
    let rpc_sources = RpcSources::Default(SolanaCluster::Mainnet);
    let rpc_cfg: Option<RpcConfig> = None;

    let params = SendTransactionParams {
        transaction: tx_b64,
        skip_preflight: Some(true),
        encoding: Some(SendTransactionEncoding::Base64),
        preflight_commitment: None,
        max_retries: None,
        min_context_slot: None,
    };

    let args = candid::encode_args((rpc_sources, rpc_cfg, params)).map_err(|e| e.to_string())?;
    let cycles: u128 = 2_000_000_000;
    let raw = call_raw128(*SOL_RPC_PRINCIPAL, "sendTransaction", args, cycles).await
        .map_err(|e| format!("sendTransaction call error: {:?}", e))?;
    let (multi,): (MultiSendTransactionResult,) = candid::decode_args(&raw).map_err(|e| format!("sendTransaction decode error: {:?}", e))?;
    match multi {
        MultiSendTransactionResult::Consistent(SendTransactionResult::Ok(sig)) => Ok(sig),
        MultiSendTransactionResult::Inconsistent(list) => {
            for (_s, r) in list {
                if let SendTransactionResult::Ok(sig) = r { return Ok(sig); }
            }
            Err("sendTransaction inconsistent and no Ok value".into())
        }
        MultiSendTransactionResult::Consistent(SendTransactionResult::Err(e)) =>
            Err(format!("sendTransaction error: {e}")),
    }
}

/* ------------------------------ public methods ------------------------------ */

#[update]
async fn get_sol_deposit_address(sol_pubkey: String) -> String {
    let user_pk = get_user_sol_pk(&sol_pubkey).await;
    bs58::encode(user_pk).into_string()
}

#[update]
async fn get_sol_balance(sol_pubkey: String) -> u64 {
    // Return 0 if the RPC fails, rather than trapping the whole call.
    let user_pk = get_user_sol_pk(&sol_pubkey).await;
    let pubkey_str = bs58::encode(user_pk).into_string();
    match sol_get_balance_lamports(pubkey_str).await {
        Ok(lamports) => lamports,
        Err(e) => {
            ic_cdk::println!("get_sol_balance error: {}", e);
            0
        }
    }
}

#[update]
async fn transfer_sol(to: String, amount: u64, sol_pubkey: String, signature: Vec<u8>, nonce: u64) -> String {
    // anti-replay
    let current_nonce = get_nonce(sol_pubkey.clone());
    if nonce != current_nonce {
        return "Invalid nonce".to_string();
    }

    // user authorization
    let message = format!("transfer_sol to {} amount {} nonce {} service_fee {}", to, amount, nonce, SERVICE_FEE_SOL).into_bytes();
    if !verify_signature(&sol_pubkey, &message, &signature) {
        return "Invalid signature".to_string();
    }

    let subaccount = derive_subaccount(&sol_pubkey);

    // charge service fee in ICP (single call + proper matching)
    let service_args = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(SERVICE_FEE_SOL),
        fee: DEFAULT_FEE,
        from_subaccount: Some(subaccount),
        to: *SERVICE_ACCOUNT,
        created_at_time: Some(Timestamp { timestamp_nanos: ic_cdk::api::time() }),
    };
    match ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, &service_args).await {
        Ok(Ok(_)) => { /* proceed */ }
        Ok(Err(e)) => { return format!("Service fee transfer failed: {:?}", e); }
        Err(e)     => { return format!("Call error for service fee: {:?}", e); }
    }

    // get a recent blockhash (slot -> block -> blockhash), finalized commitment
    let slot = match sol_get_finalized_slot().await {
        Ok(s) => s,
        Err(e) => return format!("Failed to get slot: {}", e),
    };
    let blockhash_b58 = match sol_get_blockhash_for_slot(slot).await {
        Ok(h) => h,
        Err(e) => return format!("Failed to get blockhash: {}", e),
    };
    let blockhash: [u8; 32] = match bs58::decode(&blockhash_b58).into_vec() {
        Ok(v) => match v.try_into() { Ok(a) => a, Err(_) => return "Invalid blockhash".into() },
        Err(_) => return "Invalid blockhash".into(),
    };

    // build and sign the transfer tx
    let from_pk = get_user_sol_pk(&sol_pubkey).await;
    let to_pk: [u8; 32] = match bs58::decode(&to).into_vec() {
        Ok(v) => match v.try_into() { Ok(a) => a, Err(_) => return "Invalid to address".into() },
        Err(_) => return "Invalid to address".into(),
    };
    // system program pubkey is 32 zero bytes
    let system_pk = [0u8; 32];
    let accounts = vec![from_pk, to_pk, system_pk];

    // header: 1 signer (from), 0 readonly signed, 1 readonly unsigned (system program)
    let header = [1u8, 0u8, 1u8];

    // system transfer data: 4-byte LE 2 + 8-byte LE lamports
    let mut data = Vec::new();
    data.extend(2u32.to_le_bytes());
    data.extend(amount.to_le_bytes());

    let instrs = vec![CompiledInstrLike {
        prog_idx: 2,         // index of system program in accounts
        accts: vec![0, 1],   // from, to
        data,
    }];

    let msg_ser = serialize_message(header, &accounts, blockhash, &instrs);

    // sign with canister's derived ed25519 key (threshold Schnorr ed25519)
    let pubkey_bytes = match bs58::decode(&sol_pubkey).into_vec() {
        Ok(b) => b,
        Err(_) => return "Invalid user pubkey".into(),
    };
    let sign_args = SignWithSchnorrArgs {
        message: msg_ser.clone(),
        derivation_path: vec![pubkey_bytes],
        key_id: KEY_ID.clone(),
        aux: None,
    };
    let arg_bytes = candid::encode_one(&sign_args).unwrap();

    let mgmt = Principal::management_canister();
    let cycles_sign: u128 = 25_000_000_000;
    let raw_sig = match call_raw128(mgmt, "sign_with_schnorr", arg_bytes, cycles_sign).await {
        Ok(r) => r,
        Err(e) => return format!("Sign error: {:?}", e),
    };
    let sig_reply: SignWithSchnorrResult = match candid::decode_one(&raw_sig) {
        Ok(s) => s,
        Err(e) => return format!("Sign decode error: {:?}", e),
    };

    // serialize final tx: <num sigs><sig><message>
    let mut tx_ser = encode_compact(1);
    tx_ser.extend(&sig_reply.signature);
    tx_ser.extend(&msg_ser);
    let tx_b64 = general_purpose::STANDARD.encode(tx_ser);

    // send the transaction
    let txid = match sol_send_transaction_b64(tx_b64).await {
        Ok(sig) => sig,
        Err(e) => return format!("Send failed: {}", e),
    };

    // bump nonce only after success
    NONCE_MAP.with(|map| {
        let mut map = map.borrow_mut();
        map.insert(sol_pubkey.clone(), current_nonce + 1);
    });

    format!("Transfer successful: txid {}", txid)
}

#[query]
fn get_deposit_address(sol_pubkey: String) -> String {
    let subaccount = derive_subaccount(&sol_pubkey);
    let account = AccountIdentifier::new(&canister_id(), &subaccount);
    hex::encode(account.as_ref())
}

#[update]
async fn get_balance(sol_pubkey: String) -> u64 {
    let subaccount = derive_subaccount(&sol_pubkey);
    let account = AccountIdentifier::new(&canister_id(), &subaccount);
    let args = ic_ledger_types::AccountBalanceArgs { account };
    ic_ledger_types::account_balance(
        MAINNET_LEDGER_CANISTER_ID,
        &args,
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

    let message = format!("transfer to {} amount {} nonce {} service_fee {}", to_hex, amount_e8s, nonce, SERVICE_FEE).into_bytes();
    if !verify_signature(&sol_pubkey, &message, &signature) {
        return "Invalid signature".to_string();
    }

    let to_bytes = match hex::decode(&to_hex) {
        Ok(b) => b,
        Err(_) => return "Invalid destination address".into(),
    };
    let to = match AccountIdentifier::from_slice(&to_bytes) {
        Ok(a) => a,
        Err(_) => return "Invalid destination address".into(),
    };

    let subaccount = derive_subaccount(&sol_pubkey);

    // service fee transfer
    let service_args = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(SERVICE_FEE),
        fee: DEFAULT_FEE,
        from_subaccount: Some(subaccount),
        to: *SERVICE_ACCOUNT,
        created_at_time: Some(Timestamp { timestamp_nanos: ic_cdk::api::time() }),
    };
    match ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, &service_args).await {
        Ok(Ok(_)) => {}, // proceed
        Ok(Err(e)) => return format!("Service fee transfer failed: {:?}", e),
        Err(e) => return format!("Call error for service fee: {:?}", e),
    }

    // main ICP transfer
    let args = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(amount_e8s),
        fee: DEFAULT_FEE,
        from_subaccount: Some(subaccount),
        to,
        created_at_time: Some(Timestamp { timestamp_nanos: ic_cdk::api::time() }),
    };

    let result = ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, &args).await;
    match result {
        Ok(Ok(block_index)) => {
            // bump nonce after success
            NONCE_MAP.with(|map| {
                let mut map = map.borrow_mut();
                map.insert(sol_pubkey.clone(), current_nonce + 1);
            });
            format!("Transfer successful: block {}", block_index)
        },
        Ok(Err(TransferError::InsufficientFunds { balance })) => {
            let icp_balance = balance.e8s() as f64 / 100_000_000.0;
            format!("Insufficient funds: balance is {:.8} ICP", icp_balance)
        },
        Ok(Err(other)) => format!("Transfer failed: {:?}", other),
        Err(call_error) => format!("Call error: {:?}", call_error),
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
