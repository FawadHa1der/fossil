
import os
import asyncio
import json
from dotenv import load_dotenv

from web3 import Web3
from web3.middleware import geth_poa_middleware


from services.external_api.client import RetryConfig
from starkware.starknet.services.api.gateway.transaction import Deploy, InvokeFunction
from starkware.starknet.compiler.compile import compile_starknet_files, get_selector_from_name
from starkware.cairo.lang.vm.crypto import pedersen_hash
from utils.types import Data
from utils.block_header import build_block_header
from utils.Signer import Signer
from utils.create_account import create_account
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net import AccountClient, KeyPair
from starknet_py.net.signer.stark_curve_signer import KeyPair, StarkCurveSigner
from starknet_py.contract import Contract
from utils.types import Data, BlockHeaderIndexes

DEFAULT_MAX_FEE = int(1e18)

testnet = "testnet"
chain_id = StarknetChainId.TESTNET
load_dotenv()

eth_provider_url = f"https://eth-goerli.alchemyapi.io/v2/{os.getenv('alchemy_api_key')}"
provider = Web3.HTTPProvider(eth_provider_url)
web3 = Web3(provider)
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

def get_gateway_client() -> GatewayClient:
    # Limit the number of retries.
    retry_config = RetryConfig(n_retries=1)
    return GatewayClient(net=testnet)

starknet_core_addr = '0xde29d060D45901Fb19ED6C6e959EB22d8626708e'

async def process_block(client, l1_headers_contract_address,  block_number , block_rlp):
    l1_headers_contract = Contract(
        l1_headers_contract_address,
        json.load(open('L1HeadersStore.json')),
        client,
    )
    tx_receipt = await (await l1_headers_contract.functions["process_block"].invoke(2**BlockHeaderIndexes.STATE_ROOT, block_number, block_rlp.length, block_rlp.values, max_fee=int(1e16))).wait_for_acceptance()
    print(f'Register process_block receipt {tx_receipt}')

async def register_computation_twap(client, twap_contract_address, start_block, end_block,parameter,  callback_address):
    twapcontract = Contract(
        twap_contract_address,
        json.load(open('TWAP.json')),
        client,
    )
    tx_receipt = await (await twapcontract.functions["register_computation"].invoke(start_block, end_block, parameter, int(callback_address, 16),max_fee=int(1e16))).wait_for_acceptance()
    print(f'Register computation receipt {tx_receipt}')

async def compute_twap(client, twap_contract_address, computation_id,
    len_headers_lengths_bytes,
    headers_lengths_bytes,
    len_headers_lengths_words,
    headers_lengths_words,
    len_concat_headers,
    concat_headers
):

    # If the ABI is known, create the contract directly (this is the preferred way).
    twapcontract = Contract(
        twap_contract_address,
        json.load(open('TWAP.json')),
        client,
    )
    tx_receipt = await (await twapcontract.functions["compute"].invoke(computation_id,
        headers_lengths_bytes,
        headers_lengths_words,
        concat_headers,max_fee=int(1e16))).wait_for_acceptance()

    print(f'compute TWAP receipt {tx_receipt}')

## Remember end_block < start_block, so we are working in backward direction from beginning start block
start_block_number = int(os.getenv('START_BLOCK')) - 1 # The block you send to L1 Messaging Contract, should be --> start_block + 1

twap_contract_address = os.getenv("STARKNET_TWAP_ADDR")
l1_headers_address = os.getenv("STARKNET_L1_HEADERS_STORE_ADDR")

twap_callback_address = os.getenv("STARKNET_TWAP_CALLBACK_ADDR")

secrets = json.load(open('secrets.json'))
gateway_client = get_gateway_client()
l2_priv_key = secrets['l2_priv_key']
l2_account_address = secrets['l2_account_address']

# There is another way of creating key_pair
key_pair = KeyPair.from_private_key(key=int(l2_priv_key))

# Instead of providing key_pair it is possible to specify a signer
signer = StarkCurveSigner(int(l2_account_address), key_pair, StarknetChainId.TESTNET)
account_client = AccountClient(client=gateway_client, address=int(l2_account_address), signer=signer)

block = dict(web3.eth.get_block(start_block_number))
block_header = build_block_header(block)
print(block_header)
block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()
print("Block Number: ", start_block_number , " ,blockhash: ", block_header.hash().hex())
loop = asyncio.new_event_loop()
loop.run_until_complete(process_block(account_client, l1_headers_address, start_block_number,  block_rlp))
loop.close()
