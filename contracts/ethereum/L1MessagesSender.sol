// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.9;

import {FormatWords64} from "./lib/FormatWords64.sol";
import {IStarknetCore} from "./interfaces/IStarknetCore.sol";


contract L1MessagesSender {
    IStarknetCore public immutable starknetCore;
    uint256 public immutable l2RecipientAddr;

    uint256 constant SUBMIT_L1_BLOCKHASH_SELECTOR = 598342674068027518481179578557554850038206119856216505601406522348670006916;

    constructor(IStarknetCore starknetCore_, uint256 l2RecipientAddr_) {
        starknetCore = starknetCore_;
        l2RecipientAddr = l2RecipientAddr_;
    }

    function sendExactBlockHashToL2(uint256 blockNumber_) external {
        bytes32 blockHash = blockhash(blockNumber_);
        require(blockHash != bytes32(0), "ERR_INVALID_BLOCK_NUMBER");
        _sendBlockHashToL2(blockHash, blockNumber_);
    }

    function sendLatestBlockHashToL2() external {
        bytes32 blockHash = blockhash(block.number - 1);
        _sendBlockHashToL2(blockHash, block.number - 1);
    }

    function _sendBlockHashToL2(bytes32 blockHash_, uint256 blockNumber_) internal {
        uint256[] memory message = new uint256[](5);
        (bytes8 hashWord1, bytes8 hashWord2, bytes8 hashWord3, bytes8 hashWord4) = FormatWords64.fromBytes32(blockHash_);

        message[0] = uint256(uint64(hashWord1));
        message[1] = uint256(uint64(hashWord2));
        message[2] = uint256(uint64(hashWord3));
        message[3] = uint256(uint64(hashWord4));
        message[4] = blockNumber_;

        starknetCore.sendMessageToL2(l2RecipientAddr, SUBMIT_L1_BLOCKHASH_SELECTOR, message);
    }
}
