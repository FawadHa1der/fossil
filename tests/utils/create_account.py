from random import randint
from utils.deploy import deploy
from utils.Signer import MockSigner
from eth_account import Account 

async def create_account(starknet):
    priv_key = randint(100000000000, 999999999999)
    signer = MockSigner(priv_key)
    L1_ADDRESS = int(Account.create().address, base=16)
    account = await deploy(starknet, "./contracts/starknet/external/Account.cairo", [signer.public_key])
    return account, signer

