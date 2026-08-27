// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BlokyzMint} from "../src/BlokyzMint.sol";
import {VRFV2PlusClient} from
    "../lib/chainlink-brownie-contracts/contracts/src/v0.8/vrf/dev/libraries/VRFV2PlusClient.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
    function prank(address msgSender) external;
    function warp(uint256 newTimestamp) external;
}

interface RawVrfConsumer {
    function rawFulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) external;
}

contract MockVrfCoordinator {
    uint256 private _nextRequestId = 1;

    function requestRandomWords(VRFV2PlusClient.RandomWordsRequest calldata)
        external
        returns (uint256 requestId)
    {
        requestId = _nextRequestId++;
    }

    function fulfill(address consumer, uint256 requestId, uint256 word) external {
        uint256[] memory words = new uint256[](1);
        words[0] = word;
        RawVrfConsumer(consumer).rawFulfillRandomWords(requestId, words);
    }
}

contract BlokyzMintAuditTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant ENTRANT = address(0x1001);
    address private constant SECOND_ENTRANT = address(0x1002);
    address private constant FAVORED_NON_ENTRANT = address(0xBEEF);
    address private constant FAVORED_ENTRANT = address(0xF00D);

    receive() external payable {}

    function testOwnerCanGiveAllRaffleNftsAndProceedsToANonEntrant() external {
        (BlokyzMint mint, MockVrfCoordinator coordinator) = _deployAndOpenRaffle(1 wei);

        vm.deal(ENTRANT, 1 wei);
        vm.prank(ENTRANT);
        mint.enterRaffle{value: 1 wei}(1);

        vm.warp(mint.raffleEnd());
        mint.setAllocatorHash(bytes32(uint256(1)));
        uint256 requestId = mint.requestRaffleSeed();
        coordinator.fulfill(address(mint), requestId, 123);

        bytes32 root = mint.allocationLeaf(FAVORED_NON_ENTRANT, mint.RAFFLE_SUPPLY(), 0);
        mint.setAllocation(root, 0);
        mint.openClaims();

        bytes32[] memory emptyProof = new bytes32[](0);
        uint256 raffleSupply = mint.RAFFLE_SUPPLY();
        vm.prank(FAVORED_NON_ENTRANT);
        mint.claimNfts(raffleSupply, 0, emptyProof, type(uint256).max);

        require(mint.entriesOf(FAVORED_NON_ENTRANT) == 0, "favored wallet entered");
        require(mint.balanceOf(FAVORED_NON_ENTRANT) == raffleSupply, "not all NFTs");

        uint256 treasuryBefore = address(this).balance;
        mint.withdrawProceeds();
        require(address(this).balance == treasuryBefore + 1 wei, "proceeds not diverted");
    }

    function testUnderstatedRefundTotalMakesLaterValidProofInsolvent() external {
        (BlokyzMint mint, MockVrfCoordinator coordinator) = _deployAndOpenRaffle(1 wei);

        vm.deal(ENTRANT, 1 wei);
        vm.prank(ENTRANT);
        mint.enterRaffle{value: 1 wei}(1);
        vm.deal(SECOND_ENTRANT, 1 wei);
        vm.prank(SECOND_ENTRANT);
        mint.enterRaffle{value: 1 wei}(1);

        vm.warp(mint.raffleEnd());
        mint.setAllocatorHash(bytes32(uint256(1)));
        uint256 requestId = mint.requestRaffleSeed();
        coordinator.fulfill(address(mint), requestId, 456);

        bytes32 firstLeaf = mint.allocationLeaf(ENTRANT, 0, 1 wei);
        bytes32 secondLeaf = mint.allocationLeaf(SECOND_ENTRANT, 0, 1 wei);
        mint.setAllocation(_hashPair(firstLeaf, secondLeaf), 1 wei);
        mint.openClaims();

        bytes32[] memory firstProof = new bytes32[](1);
        firstProof[0] = secondLeaf;
        vm.prank(ENTRANT);
        mint.claimRefund(0, 1 wei, firstProof, ENTRANT);

        bytes32[] memory secondProof = new bytes32[](1);
        secondProof[0] = firstLeaf;
        vm.prank(SECOND_ENTRANT);
        (bool success,) = address(mint).call(
            abi.encodeCall(mint.claimRefund, (0, 1 wei, secondProof, SECOND_ENTRANT))
        );
        require(!success, "under-reserved refund unexpectedly paid");
        require(address(mint).balance == 1 wei, "remaining deposit missing");
    }

    function testOwnerCanChooseOnePayingEntrantAsTheOnlyWinner() external {
        (BlokyzMint mint, MockVrfCoordinator coordinator) = _deployAndOpenRaffle(1 wei);

        vm.deal(ENTRANT, 1 wei);
        vm.prank(ENTRANT);
        mint.enterRaffle{value: 1 wei}(1);
        vm.deal(FAVORED_ENTRANT, 1 wei);
        vm.prank(FAVORED_ENTRANT);
        mint.enterRaffle{value: 1 wei}(1);

        vm.warp(mint.raffleEnd());
        mint.setAllocatorHash(bytes32(uint256(1)));
        uint256 requestId = mint.requestRaffleSeed();
        coordinator.fulfill(address(mint), requestId, 999);

        bytes32 root = mint.allocationLeaf(FAVORED_ENTRANT, 1, 0);
        mint.setAllocation(root, 0);
        mint.openClaims();

        bytes32[] memory emptyProof = new bytes32[](0);
        vm.prank(FAVORED_ENTRANT);
        mint.claimNfts(1, 0, emptyProof, 1);

        require(mint.entriesOf(ENTRANT) == 1, "other wallet did not enter");
        require(mint.entriesOf(FAVORED_ENTRANT) == 1, "favored wallet did not enter");
        require(mint.balanceOf(FAVORED_ENTRANT) == 1, "favored entrant did not receive NFT");

        vm.prank(ENTRANT);
        (bool otherEntrantCanClaim, bytes memory revertData) = address(mint).call(
            abi.encodeCall(mint.claimNfts, (1, 0, emptyProof, 1))
        );
        require(!otherEntrantCanClaim, "other entrant unexpectedly received a claim");
        require(
            revertData.length >= 4 && bytes4(revertData) == BlokyzMint.InvalidProof.selector,
            "other entrant did not fail because of the owner-selected allocation"
        );

        uint256 treasuryBefore = address(this).balance;
        mint.withdrawProceeds();
        require(address(this).balance == treasuryBefore + 2 wei, "entry deposits not withdrawn");
    }

    function testRetryDiscardsTheEarlierVrfResult() external {
        (BlokyzMint mint, MockVrfCoordinator coordinator) = _deployAndOpenRaffle(1 wei);

        vm.warp(mint.raffleEnd());
        mint.setAllocatorHash(bytes32(uint256(1)));
        uint256 firstRequestId = mint.requestRaffleSeed();

        vm.warp(block.timestamp + mint.SEED_RETRY_COOLDOWN());
        uint256 secondRequestId = mint.requestRaffleSeed();

        coordinator.fulfill(address(mint), firstRequestId, 111);
        require(mint.raffleSeed() == 0, "stale result was accepted");

        coordinator.fulfill(address(mint), secondRequestId, 222);
        require(mint.raffleSeed() == 222, "latest result was not accepted");
    }

    function _deployAndOpenRaffle(uint256 price)
        private
        returns (BlokyzMint mint, MockVrfCoordinator coordinator)
    {
        coordinator = new MockVrfCoordinator();
        mint = new BlokyzMint(
            price,
            address(this),
            address(coordinator),
            1,
            bytes32(uint256(1)),
            address(this),
            0
        );
        mint.configureRaffle(uint64(block.timestamp + 1), uint64(block.timestamp + 100));
        vm.warp(block.timestamp + 1);
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(bytes.concat(a, b)) : keccak256(bytes.concat(b, a));
    }
}
