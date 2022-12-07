from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.compiler.compile import compile_starknet_files


async def deploy(starknet, path, constructor_calldata):
    contract_class = compile_starknet_files([path], debug_info=True)
    contract = await starknet.deploy(
        contract_class=contract_class,
        constructor_calldata=constructor_calldata
    )
        #   contract = StarknetContract(
        #   state=state, abi=contract_class.abi, contract_address=contract_address)

    return contract