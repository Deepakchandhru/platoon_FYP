import os
import sys
from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version
from solcx.exceptions import SolcNotInstalled

SOLC_VERSION = "0.8.17"
PROVIDER = "http://127.0.0.1:7545"
GAS_LIMIT = 3_000_000

def ensure_solc(version=SOLC_VERSION):
    try:
        set_solc_version(version)
    except SolcNotInstalled:
        print(f"solc {version} not found — installing...")
        install_solc(version)
        set_solc_version(version)

def load_contract_source():
    base = os.path.dirname(__file__)
    for name in ("VehicleTrust.sol", "vehicleTrust.sol"):
        path = os.path.join(base, name)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
    raise FileNotFoundError("VehicleTrust.sol not found in script directory.")

def compile_contract(source):
    compiled = compile_source(source)
    _, contract_interface = compiled.popitem()
    abi = contract_interface.get("abi")
    bytecode = contract_interface.get("bin")
    if not abi or not bytecode:
        raise RuntimeError("Compilation failed or returned empty ABI/bytecode.")
    print("Compiled OK: ABI length", len(abi), "Bytecode length", len(bytecode))
    return abi, bytecode

def connect_provider():
    w3 = Web3(Web3.HTTPProvider(PROVIDER))
    if not w3.is_connected():
        raise ConnectionError(f"Unable to connect to provider at {PROVIDER}")
    print("Connected to provider:", PROVIDER, "chainId:", w3.eth.chain_id)
    return w3

def sign_and_send(w3, txn_dict, private_key):
    signed = w3.eth.account.sign_transaction(txn_dict, private_key=private_key)
    raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None) or getattr(signed, "raw_tx", None)
    if raw is None:
        # try mapping access if the object supports it
        try:
            raw = signed["rawTransaction"]
        except Exception:
            raise RuntimeError("Signed transaction missing raw bytes (no rawTransaction/raw_transaction/raw_tx).")
    tx_hash = w3.eth.send_raw_transaction(raw)
    print("Sent raw tx:", tx_hash.hex())
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print("Receipt status:", receipt.status, "tx:", receipt.transactionHash.hex())
    return receipt

def build_deploy_tx(w3, Contract, deployer, chain_id):
    base = {
        "from": deployer,
        "nonce": w3.eth.get_transaction_count(deployer),
        "gas": GAS_LIMIT,
        "chainId": chain_id,
    }
    try:
        base.update({
            "maxFeePerGas": w3.to_wei("2", "gwei"),
            "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
        })
        return Contract.constructor().build_transaction(base)
    except Exception:
        base["gasPrice"] = w3.to_wei("20", "gwei")
        return Contract.constructor().build_transaction(base)

def build_call_tx(w3, fn, account, chain_id):
    base = {
        "from": account,
        "nonce": w3.eth.get_transaction_count(account),
        "gas": GAS_LIMIT,
        "chainId": chain_id,
    }
    try:
        base.update({
            "maxFeePerGas": w3.to_wei("2", "gwei"),
            "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
        })
        return fn.build_transaction(base)
    except Exception:
        base["gasPrice"] = w3.to_wei("20", "gwei")
        return fn.build_transaction(base)

def deploy_contract(w3, abi, bytecode, deployer_account, private_key=None):
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    chain_id = w3.eth.chain_id
    if private_key:
        tx = build_deploy_tx(w3, Contract, deployer_account, chain_id)
        receipt = sign_and_send(w3, tx, private_key)
    else:
        tx_hash = Contract.constructor().transact({"from": deployer_account, "gas": GAS_LIMIT})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print("Sent unlocked tx:", tx_hash.hex())
    if receipt.status != 1:
        raise RuntimeError(f"Deployment transaction reverted or failed: {receipt}")
    print("Deployed at:", receipt.contractAddress)
    return w3.eth.contract(address=receipt.contractAddress, abi=abi)

def call_set_trust(w3, contract, account, score, private_key=None):
    fn = contract.functions.setTrustScore("V101", score)
    chain_id = w3.eth.chain_id
    if private_key:
        tx = build_call_tx(w3, fn, account, chain_id)
        receipt = sign_and_send(w3, tx, private_key)
    else:
        tx_hash = fn.transact({"from": account, "gas": GAS_LIMIT})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print("Sent unlocked tx:", tx_hash.hex())
    if receipt.status != 1:
        raise RuntimeError("setTrustScore transaction failed.")
    print("setTrustScore mined.")

def main():
    ensure_solc()
    source = load_contract_source()
    abi, bytecode = compile_contract(source)

    w3 = connect_provider()

    accounts = w3.eth.accounts
    if not accounts:
        raise RuntimeError("No accounts returned by provider. Set PRIVATE_KEY.")
    deployer = accounts[0]

    # Replace with your Ganache private key or set via env var PRIVATE_KEY
    private_key = os.environ.get("PRIVATE_KEY") or "0x8122b36921f7a841a77edc04f7758a9ddbbc88c6f6bd4e1a620a6c73c1516ce5"
    if private_key:
        acct = w3.eth.account.from_key(private_key).address
        if acct.lower() != deployer.lower():
            print("Warning: PRIVATE_KEY address", acct, "does not match provider first account", deployer)
            deployer = acct

    print("Using deployer:", deployer, "private_key_set:", bool(private_key))

    try:
        contract = deploy_contract(w3, abi, bytecode, deployer, private_key=private_key)
    except Exception as e:
        print("Deployment failed:", e)
        print("If using Ganache UI, copy an account's private key into env PRIVATE_KEY and retry.")
        sys.exit(1)

    try:
        call_set_trust(w3, contract, deployer, 82, private_key=private_key)
    except Exception as e:
        print("setTrustScore failed:", e)
        sys.exit(1)

    score = contract.functions.getTrustScore("V101").call()
    print("Trust score for V101:", score)

if __name__ == "__main__":
    main()