
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
from starknet_py.contract import Contract as CairoContract
from utils.types import Data, BlockHeaderIndexes

from web3.contract import Contract, ContractFunction

# from uniswap.EtherClient import web3_client
# from uniswap.utils.consts import ERC20_TOKENS, ROPSTEN
# from uniswap.utils.erc20token import EIP20Contract
# from uniswap.v3.main import UniswapV3




from uniswap import Uniswap

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
    l1_headers_contract = CairoContract(
        l1_headers_contract_address,
        json.load(open('L1HeadersStore.json')),
        client,
    )
    tx_receipt = await (await l1_headers_contract.functions["process_block"].invoke(2**BlockHeaderIndexes.GAS_USED, block_number, block_rlp.length, block_rlp.values, max_fee=int(1e16))).wait_for_acceptance()
    print(f'Register computation receipt {tx_receipt}')


async def prove_account(client, fact_registry_address,  block_number , option_set, account_words64, flat_account_proof_sizes_bytes, flat_account_proof_sizes_words, flat_account_proof):
    fact_registry_contract = CairoContract(
        fact_registry_address,
        json.load(open('FactsRegistry.json')),
        client,
    )
    #[2**BlockHeaderIndexes.GAS_USED] + [block['number']] + [block_rlp.length] + [len(block_rlp.values)] + block_rlp.values
    tx_receipt = await (await fact_registry_contract.functions["prove_account"].invoke(option_set, block_number, account_words64, flat_account_proof_sizes_bytes, flat_account_proof_sizes_words, flat_account_proof, max_fee=int(1e16))).wait_for_acceptance()
    print(f'Register computation receipt {tx_receipt}')


async def register_computation_twap(client, twap_contract_address, start_block, end_block,parameter,  callback_address):
    twapcontract = CairoContract(
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
    twapcontract = CairoContract(
        twap_contract_address,
        json.load(open('TWAP.json')),
        client,
    )
    tx_receipt = await (await twapcontract.functions["compute"].invoke(computation_id,
        headers_lengths_bytes,
        headers_lengths_words,
        concat_headers,max_fee=int(1e16))).wait_for_acceptance()

    # twap_compute_tx = InvokeFunction(
    #         contract_address=int(twap_contract_address, 16),
    #         entry_point_selector=get_selector_from_name('compute'),
    #         calldata=_calldata,
    #         signature=[],
    #         max_fee=0,
    #         version=0)
    # tx_receipt = await client.add_transaction(twap_compute_tx)

    print(f'compute TWAP receipt {tx_receipt}')


## Remember end_block < start_block, so we are working in backward direction from beginning start block
start_block_number = int(os.getenv('START_BLOCK')) - 1 # The block you send to L1 Messaging Contract, should be --> start_block + 1
parameter_num = 15 # basefee --> 15, difficulty --> 7, gas_used --> 10

twap_contract_address = os.getenv("STARKNET_TWAP_ADDR")
l1_headers_address = os.getenv("STARKNET_L1_HEADERS_STORE_ADDR")
twap_callback_address = os.getenv("STARKNET_TWAP_CALLBACK_ADDR")
fact_registry_address = os.getenv("STARKNET_FACTS_REGISTRY_ADDR")

secrets = json.load(open('secrets.json'))
gateway_client = get_gateway_client()
l2_priv_key = secrets['l2_priv_key']
l2_account_address = secrets['l2_account_address']

# There is another way of creating key_pair
key_pair = KeyPair.from_private_key(key=int(l2_priv_key))

# Instead of providing key_pair it is possible to specify a signer
signer = StarkCurveSigner(int(l2_account_address), key_pair, StarknetChainId.TESTNET)
account_client = AccountClient(client=gateway_client, address=int(l2_account_address), signer=signer)

#######################
eth = "0x0000000000000000000000000000000000000000"
bat = "0x0D8775F648430679A709E98d2b0Cb6250d2887EF"
dai = "0xdc31ee1784292379fbb2964b3b9c4124d8f89c60"
weth = "0xB4FBF271143F4FBf7B91A5ded31805e42b2208d6"
usdc = "0x07865c6e87b9f70255377e024ace6630c1eaa37f"

# client = web3_client.EtherClient(http_url=eth_provider_url)
# print(client.w3.eth.block_number)

# uni = UniswapV3(client)
# print(uni.factory.get_functions())
# print(uni.factory.functions.getPool(weth, dai, 3000).call())

# print(client.w3.eth.chain_id)

# print(uni.factory.abi)
# print(uni.factory.functions.getPool(usdc.address, weth, 500).call())

####################

uniswap = Uniswap(address=os.getenv("ETHEREUM_PUBKEY"), private_key=secrets["l1_priv_key"], version=3, provider=eth_provider_url)
weth_address = uniswap.get_weth_address()
print(f'WETH address {weth_address}')
# pool_contract = uniswap.get_pool_instance(web3.toChecksumAddress(weth_address) , web3.toChecksumAddress(dai))
pool_contract = uniswap.get_pool_instance( web3.toChecksumAddress(usdc), web3.toChecksumAddress(weth), fee=3000)

# price_input = uniswap.get_price_input(web3.toChecksumAddress(weth), web3.toChecksumAddress(usdc), 3000, 1000000000000000000)
# print(f'Price input {price_input}')
# print(f'Pool contract address {pool_contract.address}')
decimals = 18
slot0Data = pool_contract.functions.slot0().call(block_identifier=start_block_number)

print("Slot0Data: ", slot0Data)
sqrtPriceX96 = slot0Data[0]

raw_price = (sqrtPriceX96 * sqrtPriceX96 * 10**decimals >> (96 * 2)) / (
    10**decimals
)

print("Price: ", raw_price)
proof = web3.eth.get_proof(pool_contract.address, [0], start_block_number)
jsonProof = web3.toJSON(proof)

print("Proof: ", jsonProof)
account_proof = list(map(lambda element: Data.from_bytes(element).to_ints(), proof['accountProof']))
flat_account_proof = []
flat_account_proof_sizes_bytes = []
flat_account_proof_sizes_words = []
for proof_element in account_proof:
    flat_account_proof += proof_element.values
    flat_account_proof_sizes_bytes += [proof_element.length]
    flat_account_proof_sizes_words += [len(proof_element.values)]

options_set = 1 # saves everything in state
l1_account_address = Data.from_hex(pool_contract.address)
account_words64 = l1_account_address.to_ints()
account_dict = {"word_1":account_words64.values[0], "word_2":account_words64.values[1], "word_3":account_words64.values[2]}

loop = asyncio.new_event_loop()
loop.run_until_complete(prove_account(account_client, fact_registry_address, start_block_number, options_set , account_dict, flat_account_proof_sizes_bytes, flat_account_proof_sizes_words, flat_account_proof))
loop.close()

# options_set = 15 # saves everything in state

# l1_account_address = Data.from_hex(trie_proofs[1]['address'])
# account_words64 = l1_account_address.to_ints()
# web3.eth.get_proof(l1_account_address.to_hex(), [start_block_number], start_block_number)

# # Preparing calldata starts here
# headers_lengths_bytes = []
# headers_lengths_words = []
# concat_headers = []
# for block_num in range(start_block_number, end_block_number - 1, -1):
#     block = dict(web3.eth.get_block(block_num))
#     block_header = build_block_header(block)
#     print(block_header)
#     block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()
#     print("Block Number: ", block_num , " ,blockhash: ", block_header.hash().hex())
#     headers_lengths_bytes.append(block_rlp.length)
#     headers_lengths_words.append(len(block_rlp.values))
#     concat_headers.extend(block_rlp.values)

# calldata = [
#     computation_id,
#     len(headers_lengths_bytes),
#     *headers_lengths_bytes,
#     len(headers_lengths_words),
#     *headers_lengths_words,
#     len(concat_headers),
#     *concat_headers
# ]
# print(calldata)
# # # Preparing calldata ends here
# loop = asyncio.new_event_loop()
# loop.run_until_complete(compute_twap(account_client, twap_contract_address,     computation_id, len(headers_lengths_bytes), headers_lengths_bytes, len(headers_lengths_words), headers_lengths_words, len(concat_headers), concat_headers))
# loop.close()