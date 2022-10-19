import asyncio
from imghdr import tests
from importlib import util
import pytest
import json
# from services.everest.external_api.base_client import RetryConfig

from starkware.starknet.services.api.gateway.transaction import Deploy, InvokeFunction
from starkware.starkware_utils.error_handling import StarkErrorCode
from starkware.starknet.definitions import fields
from starkware.starknet.compiler.compile import compile_starknet_files, get_selector_from_name
from Signer import MockSigner
from starkware.starknet.definitions import constants, fields
from starknet_py.net import AccountClient
from starknet_py.contract import Contract
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net import AccountClient, KeyPair
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.signer.stark_curve_signer import KeyPair, StarkCurveSigner
import os 

from web3 import Web3
from web3 import Account
from random import randint

DEFAULT_MAX_FEE = int(1e18)

testnet = "testnet"
chain_id = StarknetChainId.TESTNET


def get_gateway_client() -> GatewayClient:
    # Limit the number of retries.
    # retry_config = RetryConfig(n_retries=1)
    return GatewayClient(net=testnet)


@pytest.mark.asyncio
async def test_create_account():
    secrets = json.load(open('secrets.json'))
    gateway_url = "https://alpha4.starknet.io/"
    gateway_client = get_gateway_client(gateway_url)
    l2_priv_key = secrets['l2_priv_key']

    account_client = await AccountClient.create_account(
        client=gateway_client, chain=StarknetChainId.TESTNET, private_key=int(l2_priv_key)
    )

    print(f"L2: public address: {account_client.address}")


@pytest.mark.asyncio
async def test_deploy():
    secrets = json.load(open('secrets.json'))
    gateway_client = get_gateway_client()
    l2_priv_key = secrets['l2_priv_key']
    l2_account_address = secrets['l2_account_address']

    # There is another way of creating key_pair
    key_pair = KeyPair.from_private_key(key=int(l2_priv_key))

    # Instead of providing key_pair it is possible to specify a signer
    signer = StarkCurveSigner(int(l2_account_address), key_pair, StarknetChainId.TESTNET)

    account_client = AccountClient(client=gateway_client, address=int(l2_account_address), signer=signer)

    eth_provider_url = f"https://eth-goerli.alchemyapi.io/v2/{secrets['alchemy_api_key']}"
    starknet_core_addr = '0xde29d060D45901Fb19ED6C6e959EB22d8626708e'

    dir_path = os.path.dirname(os.path.realpath(__file__))
    contract_path = os.path.join(dir_path, 'contracts', 'starknet', 'L1MessagesProxy.cairo')
    deployment_result = await Contract.deploy(
        client=account_client, compilation_source=['/Users/fawad/ethapps/fossil/contracts/starknet/L1MessagesProxy.cairo']
    )

    # Wait until deployment transaction is accepted
    await deployment_result.wait_for_acceptance()
    # Get deployed contract
    l2_msg_contract = deployment_result.deployed_contract
    
    deployment_result = await Contract.deploy(
        client=account_client, compilation_source=['/Users/fawad/ethapps/fossil/contracts/starknet/L1HeadersStore.cairo'], search_paths=['/Users/fawad/ethapps/fossil/contracts']
    )
    # Wait until deployment transaction is accepted
    await deployment_result.wait_for_acceptance()
    # Get deployed contract
    l2_headers_contract = deployment_result.deployed_contract


    # Deploy L1 sender contract
    # Load compiled contract's bytecode and abi
    f = open('build/contracts/L1MessagesSender.json')
    contract_build = json.load(f)
    w3 = Web3(Web3.HTTPProvider(eth_provider_url))

    deployer_priv_key = secrets['l1_priv_key']

    account = Account.from_key(deployer_priv_key)
    # Load deployer account
    w3.eth.default_account = account

    L1MessagesSender = w3.eth.contract(abi=contract_build['abi'], bytecode=contract_build['bytecode'])
    deployment_tx = L1MessagesSender.constructor(starknet_core_addr, l2_msg_contract.address).buildTransaction({
        'from': account.address,
        'nonce': w3.eth.getTransactionCount(account.address),
        'gas': 2000000,
        'gasPrice': w3.toWei('20', 'gwei')
    })

    signed = account.sign_transaction(deployment_tx)
    tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction).hex()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    l1_contract_addr = tx_receipt.contractAddress

    # Initialize L1HeadersStore contract - Starknet
    await (await l2_headers_contract.functions["initialize"].invoke(int(l2_msg_contract.address),max_fee=int(1e16))).wait_for_acceptance()
    # Initialize and L1MessagingContract- Starknet
    l2_msg_contract_owner = int(l2_account_address)
    await (await l2_msg_contract.functions["initialize"].invoke(int(l1_contract_addr, 16), l2_headers_contract.address, l2_msg_contract_owner, max_fee=int(1e16))).wait_for_acceptance()
    deployment_result = await Contract.deploy(
        client=account_client, compilation_source=['/Users/fawad/ethapps/fossil/contracts/starknet/TWAP.cairo'], search_paths=['/Users/fawad/ethapps/fossil/contracts']
    )

    # Wait until deployment transaction is accepted
    await deployment_result.wait_for_acceptance()
    # Get deployed contract
    twap_contract = deployment_result.deployed_contract
    await (await twap_contract.functions["initialize"].invoke(l2_headers_contract.address, max_fee=int(1e16))).wait_for_acceptance()


    deployment_result = await Contract.deploy(
        client=account_client, compilation_source=['/Users/fawad/ethapps/fossil/contracts/starknet/FactsRegistry.cairo'], search_paths=['/Users/fawad/ethapps/fossil/contracts']
    )

    # Wait until deployment transaction is accepted
    await deployment_result.wait_for_acceptance()
    # Get deployed contract
    facts_registry_contract = deployment_result.deployed_contract

    await (await facts_registry_contract.functions["initialize"].invoke(l2_headers_contract.address, max_fee=int(1e16))).wait_for_acceptance()

    print('\n')
    print(f"L1: contract address: {l1_contract_addr}")
    print(f"Starknet: L1 headers contract address: {hex(l2_headers_contract.address)}")
    print(f"Starknet: L1 messages recipient: {hex(l2_msg_contract.address)}")
    print(f"Starknet: Facts registry: {hex(facts_registry_contract.address)}")
    print(f"Starknet: TWAP: {hex(twap_contract.address)}")

    assert 1 == 1


