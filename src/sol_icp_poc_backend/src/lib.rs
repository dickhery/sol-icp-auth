#[allow(deprecated)]  // Suppresses any residual deprecation warnings
use ic_cdk::{export_candid, query, update};
use ic_cdk::api::canister_self as canister_id;
use ic_cdk::api::call::Call;  // New import for Call builder
use ic_cdk::management_canister::{SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs, SignWithSchnorrArgs, SignWithSchnorrResult};
use ic_principal::Principal;
use ic_ledger_types::{
    AccountIdentifier, Memo, Subaccount, Timestamp, Tokens, TransferArgs, TransferError, DEFAULT_FEE,
    MAINNET_LEDGER_CANISTER_ID,
};
use ic_stable_structures::{memory_manager::{MemoryId, MemoryManager, VirtualMemory}, DefaultMemoryImpl, StableBTreeMap};
use sha2::{Digest, Sha224, Sha256};
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
    static ref SERVICE_ACCOUNT: AccountIdentifier = AccountIdentifier::from_hex("573292a9fdfff9ba7e23bcab9a99ab7db2a96c2e6697cf401a837f1c3a3280ed").unwrap();
    static ref KEY_ID: SchnorrKeyId = SchnorrKeyId { algorithm: SchnorrAlgorithm::Ed25519, name: "key_1".to_string() };
}

#[derive(CandidType, Deserialize, Clone)]
enum CommitmentLevel {
    Finalized,
}

#[derive(CandidType, Deserialize, Clone)]
enum ConsensusStrategy {
    Equality,
}

#[derive(CandidType, Deserialize, Clone)]
struct RpcConfig {
    response_consensus: Option<ConsensusStrategy>,
}

#[derive(CandidType, Deserialize, Clone)]
struct GetBalanceParams {
    commitment: Option<CommitmentLevel>,
}

#[derive(CandidType, Deserialize, Clone)]
struct GetSlotParams {
    commitment: Option<CommitmentLevel>,
}

#[derive(CandidType, Deserialize, Clone)]
enum TransactionDetails {
    None,
}

#[derive(CandidType, Deserialize, Clone)]
struct GetBlockParams {
    commitment: Option<CommitmentLevel>,
    transaction_details: Option<TransactionDetails>,
    rewards: Option<bool>,
}

#[derive(CandidType, Deserialize, Clone)]
struct GetBlockResult {
    blockhash: String,
}

#[derive(CandidType, Deserialize, Clone)]
struct SendTransactionParams {
    skip_preflight: bool,
}

#[derive(CandidType, Deserialize, Clone)]
enum RpcSources {
    Default(SolanaCluster),
}

#[derive(CandidType, Deserialize, Clone)]
enum SolanaCluster {
    Mainnet,
}

type Memory = VirtualMemory<DefaultMemoryImpl>;
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static NONCE_MAP: RefCell<StableBTreeMap<String, u64, Memory>> = RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))));
}

const SERVICE_FEE: u64 = 10000; // 0.0001 ICP in e8s for ICP transfers
const SERVICE_FEE_SOL: u64 = 20000; // 0.0002 ICP in e8s for SOL operations

#[derive(Clone)]
struct CompiledInstrLike {
    prog_idx: u8,
    accts: Vec<u8>,
    data: Vec<u8>,
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

#[update]
async fn get_sol_deposit_address(sol_pubkey: String) -> String {
    let user_pk = get_user_sol_pk(&sol_pubkey).await;
    bs58::encode(user_pk).into_string()
}

#[update]
async fn get_sol_balance(sol_pubkey: String) -> u64 {
    let user_pk = get_user_sol_pk(&sol_pubkey).await;
    let pubkey_str = bs58::encode(user_pk).into_string();
    let rpc_sources = candid::encode_one(RpcSources::Default(SolanaCluster::Mainnet)).unwrap();
    let rpc_config = candid::encode_one(Option::Some(RpcConfig { response_consensus: Some(ConsensusStrategy::Equality) })).unwrap();
    let params = candid::encode_one(Option::Some(GetBalanceParams { commitment: Some(CommitmentLevel::Finalized) })).unwrap();
    let arg_tuple = (rpc_sources, rpc_config, pubkey_str, params);
    let encoded_arg = candid::encode_args(arg_tuple).unwrap();
    let cycles: u128 = 1_000_000_000;
    let response = Call::unbounded_wait(*SOL_RPC_PRINCIPAL, "getBalance")
        .with_raw_args(&encoded_arg)
        .with_cycles(cycles)
        .await
        .map_err(|err| ic_cdk::trap(&format!("Call error: {:?}", err)))
        .unwrap();
    // ← use .reply here
    let raw_res: Vec<u8> = response.reply;
    let (balance_res,): (u64,) = candid::decode_args(&raw_res).unwrap();
    balance_res
}

#[update]
async fn transfer_sol(to: String, amount: u64, sol_pubkey: String, signature: Vec<u8>, nonce: u64) -> String {
    let current_nonce = get_nonce(sol_pubkey.clone());
    if nonce != current_nonce {
        return "Invalid nonce".to_string();
    }

    let message = format!("transfer_sol to {} amount {} nonce {} service_fee {}", to, amount, nonce, SERVICE_FEE_SOL).into_bytes();

    if !verify_signature(&sol_pubkey, &message, &signature) {
        return "Invalid signature".to_string();
    }

    let subaccount = derive_subaccount(&sol_pubkey);

    // Service fee transfer (in ICP)
    let service_args = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(SERVICE_FEE_SOL),
        fee: DEFAULT_FEE,
        from_subaccount: Some(subaccount),
        to: *SERVICE_ACCOUNT,
        created_at_time: Some(Timestamp { timestamp_nanos: ic_cdk::api::time() }),
    };
    match ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, &service_args).await {
        Ok(Ok(_)) => {}, // Proceed
        Ok(Err(e)) => return format!("Service fee transfer failed: {:?}", e),
        Err(e) => return format!("Call error for service fee: {:?}", e),
    }

    // Fetch slot
    let rpc_sources = candid::encode_one(RpcSources::Default(SolanaCluster::Mainnet)).unwrap();
    let rpc_config = candid::encode_one(Option::Some(RpcConfig { response_consensus: Some(ConsensusStrategy::Equality) })).unwrap();
    let slot_params = candid::encode_one(Option::Some(GetSlotParams { commitment: Some(CommitmentLevel::Finalized) })).unwrap();
    let arg_tuple = (rpc_sources.clone(), rpc_config.clone(), slot_params);
    let encoded_arg = candid::encode_args(arg_tuple).unwrap();
    let cycles: u128 = 1_000_000_000;
    let response = Call::unbounded_wait(*SOL_RPC_PRINCIPAL, "getSlot")
        .with_raw_args(&encoded_arg)
        .with_cycles(cycles)
        .await
        .map_err(|err| ic_cdk::trap(&format!("Call error: {:?}", err)))
        .unwrap();
    let raw_res: Vec<u8> = response.body;
    let (slot,): (u64,) = candid::decode_args(&raw_res).unwrap();

    // Fetch block
    let block_params = candid::encode_one(Option::Some(GetBlockParams {
        commitment: Some(CommitmentLevel::Finalized),
        transaction_details: Some(TransactionDetails::None),
        rewards: Some(false),
    })).unwrap();
    let arg_tuple = (rpc_sources.clone(), rpc_config.clone(), slot, block_params);
    let encoded_arg = candid::encode_args(arg_tuple).unwrap();
    let cycles: u128 = 2_000_000_000;
    let response = Call::unbounded_wait(*SOL_RPC_PRINCIPAL, "getBlock")
        .with_raw_args(&encoded_arg)
        .with_cycles(cycles)
        .await
        .map_err(|err| ic_cdk::trap(&format!("Call error: {:?}", err)))
        .unwrap();
    let raw_res: Vec<u8> = response.body;
    let (block,): (GetBlockResult,) = candid::decode_args(&raw_res).unwrap();
    let blockhash_base58 = block.blockhash;
    let blockhash: [u8; 32] = bs58::decode(&blockhash_base58)
        .into_vec()
        .unwrap_or_else(|_| ic_cdk::trap("Invalid blockhash"))
        .try_into()
        .unwrap();

    // Construct tx
    let from_pk = get_user_sol_pk(&sol_pubkey).await;
    let to_pk: [u8; 32] = bs58::decode(&to)
        .into_vec()
        .unwrap_or_else(|_| ic_cdk::trap("Invalid to address"))
        .try_into()
        .unwrap();
    let system_pk = [0u8; 32];
    let accounts = vec![from_pk, to_pk, system_pk];
    let header = [1u8, 0u8, 1u8];
    let mut data = Vec::new();
    data.extend(2u32.to_le_bytes());
    data.extend(amount.to_le_bytes());
    let instrs = vec![CompiledInstrLike {
        prog_idx: 2,
        accts: vec![0, 1],
        data,
    }];
    let msg_ser = serialize_message(header, &accounts, blockhash, &instrs);

    // Sign (low-level call with cycles)
    let pubkey_bytes = bs58::decode(&sol_pubkey).into_vec().unwrap();
    let derivation_path = vec![pubkey_bytes];
    let sign_args = SignWithSchnorrArgs {
        message: msg_ser.clone(),
        derivation_path,
        key_id: KEY_ID.clone(),
        aux: None,
    };
    let cycles_sign: u128 = 25_000_000_000;
    let arg_bytes = candid::encode_one(&sign_args).unwrap();
    let mgmt = Principal::management_canister();
    let response = Call::unbounded_wait(mgmt, "sign_with_schnorr")
        .with_raw_args(&arg_bytes)
        .with_cycles(cycles_sign)
        .await
        .map_err(|err| ic_cdk::trap(&format!("Sign error: {:?}", err)))
        .unwrap();
    let raw_res: Vec<u8> = response.body;
    let sig_reply: SignWithSchnorrResult = candid::decode_one(&raw_res).unwrap();

    // Serialize tx
    let mut tx_ser = encode_compact(1);
    tx_ser.extend(&sig_reply.signature);
    tx_ser.extend(&msg_ser);
    let tx_b64 = general_purpose::STANDARD.encode(tx_ser);

    // Send
    let send_params = candid::encode_one(Option::Some(SendTransactionParams { skip_preflight: true })).unwrap();
    let arg_tuple = (rpc_sources, rpc_config, tx_b64, send_params);
    let encoded_arg = candid::encode_args(arg_tuple).unwrap();
    let cycles: u128 = 1_000_000_000;
    let response = Call::unbounded_wait(*SOL_RPC_PRINCIPAL, "sendTransaction")
        .with_raw_args(&encoded_arg)
        .with_cycles(cycles)
        .await
        .map_err(|err| ic_cdk::trap(&format!("Send error: {:?}", err)))
        .unwrap();
    let raw_res: Vec<u8> = response.body;
    let (txid,): (String,) = candid::decode_args(&raw_res).unwrap();

    // Increment nonce after success
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

    NONCE_MAP.with(|map| {
        let mut map = map.borrow_mut();
        map.insert(sol_pubkey.clone(), current_nonce + 1);
    });

    let message = format!("transfer to {} amount {} nonce {} service_fee {}", to_hex, amount_e8s, nonce, SERVICE_FEE).into_bytes();

    if !verify_signature(&sol_pubkey, &message, &signature) {
        return "Invalid signature".to_string();
    }

    let to_bytes = hex::decode(&to_hex).unwrap_or_default();
    let to = AccountIdentifier::from_slice(&to_bytes).unwrap_or(AccountIdentifier::new(&Principal::anonymous(), &Subaccount([0; 32])));

    let subaccount = derive_subaccount(&sol_pubkey);

    // Service fee transfer
    let service_args = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(SERVICE_FEE),
        fee: DEFAULT_FEE,
        from_subaccount: Some(subaccount),
        to: *SERVICE_ACCOUNT,
        created_at_time: Some(Timestamp { timestamp_nanos: ic_cdk::api::time() }),
    };
    match ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, &service_args).await {
        Ok(Ok(_)) => {}, // Success, proceed
        Ok(Err(e)) => return format!("Service fee transfer failed: {:?}", e),
        Err(e) => return format!("Call error for service fee: {:?}", e),
    }

    // Main transfer
    let args = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(amount_e8s),
        fee: DEFAULT_FEE,
        from_subaccount: Some(subaccount),
        to,
        created_at_time: Some(Timestamp { timestamp_nanos: ic_cdk::api::time() }),
    };

    match ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, &args).await {
        Ok(Ok(block_index)) => format!("Transfer successful: block {}", block_index),
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