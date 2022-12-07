
from dotenv import load_dotenv
import os

from web3 import Web3
from web3.middleware import geth_poa_middleware
from dotenv import load_dotenv

load_dotenv()

eth_provider_url = f"https://eth-goerli.alchemyapi.io/v2/{os.getenv('alchemy_api_key')}"

provider = Web3.HTTPProvider(eth_provider_url)
web3 = Web3(provider)
# web3.middleware_onion.inject(geth_poa_middleware, layer=0)

print(web3.eth.get_block(int(os.getenv('START_BLOCK'))))