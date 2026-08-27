// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ERC721A} from "erc721a/contracts/ERC721A.sol";
import {ICreatorToken} from "@limitbreak/creator-token-standards/interfaces/ICreatorToken.sol";
import {ITransferValidator} from "@limitbreak/creator-token-standards/interfaces/ITransferValidator.sol";
import {
    BasicRoyalties
} from "@limitbreak/creator-token-standards/programmable-royalties/BasicRoyalties.sol";
import {
    VRFConsumerBaseV2Plus
} from "@chainlink/contracts/src/v0.8/vrf/dev/VRFConsumerBaseV2Plus.sol";
import {VRFV2PlusClient} from "@chainlink/contracts/src/v0.8/vrf/dev/libraries/VRFV2PlusClient.sol";
import {ERC2981} from "@openzeppelin/contracts/token/common/ERC2981.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title BlokyzMint
/// @notice ERC721A raffle mint for the Blokyz collection with a minimal ERC-721C-style
///         transfer-validator surface. The contract inherits base ERC721A directly rather
///         than Limit Break's `ERC721AC` wrapper: the wrapper's automatic validator
///         approval makes the configured validator an operator for every holder and skips
///         validation when the validator itself is the caller, which is a confiscation
///         path. Here the validator is consulted on every real transfer, is never granted
///         any approval, and gets no special treatment as a caller. Token ids are
///         sequential from 1 in mint order (`_startTokenId`), so the presale must be
///         airdropped before any team or raffle mint — enforced on-chain — which keeps
///         ids 1..presaleMinted as the presale block.
///
/// Lifecycle:
///  1. Presale       — owner airdrops up to `PRESALE_MAX_SUPPLY` tokens, taking ids from 1.
///                     All tokens are transfer-locked until claims open.
///  2. Raffle        — timebound entry window. Wallets commit `entryPrice` per entry,
///                     uncapped and oversubscribable. The first entry crossing
///                     `RAFFLE_SUPPLY` cumulative entries fixes the close at exactly
///                     24 hours later (the announced closing rule); the configured end
///                     is only a backstop for a raffle that never reaches the threshold.
///                     The window and price are immutable once the first entry lands.
///  3. Seed (VRF)    — after the window closes (and the allocator hash is committed),
///                     Chainlink VRF v2.5 supplies the raffle seed on-chain. The
///                     metadata provenance hash is deliberately NOT required here: art
///                     production must never hold up the draw, so reveal fairness runs
///                     on its own seed (step 7).
///  4. Allocation    — the winner set is computed off-chain as a pure deterministic
///                     function of (on-chain entries, raffle seed) and posted as a
///                     Merkle root of (wallet, nftAmount, refundWei). Anyone can
///                     recompute the allocation from chain data and verify the root
///                     against the allocator committed in step 3.
///  5. Claims        — `openClaims()` freezes the root, unlocks trading, and opens the
///                     pull-based claim window. NFT and refund rights are independent:
///                     NFTs are claimable incrementally in caller-bounded chunks and the
///                     refund can be sent to any chosen recipient, so a nonpayable
///                     entrant or an oversized entitlement can never strand a claim.
///  6. Safety valves — if the owner never finalizes settlement, every entrant can pull
///                     `entriesOf * entryPrice` back after `SETTLEMENT_TIMEOUT`; claims
///                     can no longer be opened past that deadline. After claims open,
///                     unclaimed refunds are sweepable after `UNCLAIMED_SWEEP_DELAY`,
///                     but NFT claim rights never expire.
///  7. Reveal        — three metadata states via unrevealed URI + base URI swaps. The
///                     reveal has its own VRF commitment, fully independent of the
///                     draw: when the art is final the owner commits `provenanceHash`
///                     (the metadata ordering), then `requestRevealSeed()` pulls a
///                     fresh VRF word. The token→metadata offset derives from that
///                     `revealSeed`, which did not exist when the ordering was
///                     committed, and `setMetadata` refuses a final base URI until the
///                     reveal seed has landed — provably fair with no deadline
///                     pressure on the artists.
contract BlokyzMint is
    ERC721A,
    ICreatorToken,
    BasicRoyalties,
    VRFConsumerBaseV2Plus,
    ReentrancyGuard,
    Pausable
{
    using Strings for uint256;

    // ─── Supply constants ──────────────────────────────────────────────────

    /// @dev Presale airdrop ceiling. Presale tokens take the first ids (1..presaleMinted).
    uint256 public constant PRESALE_MAX_SUPPLY = 1_750;
    /// @dev Guaranteed team allocation, exempt from the raffle draw.
    uint256 public constant TEAM_ALLOCATION = 750;
    /// @dev NFTs distributable through the raffle claim.
    uint256 public constant RAFFLE_SUPPLY = 7_500;
    uint256 public constant MAX_SUPPLY = PRESALE_MAX_SUPPLY + TEAM_ALLOCATION + RAFFLE_SUPPLY;

    /// @dev Ownership-slot stride for batch mints. ERC721A stores one owner record per batch and
    ///      resolves the rest by walking back to it, so an unbounded batch would make the first
    ///      transfer of a late token in a large airdrop read hundreds of cold slots. Minting in
    ///      chunks of this size caps that walk while keeping mints an order of magnitude cheaper
    ///      than one storage write per token.
    uint256 public constant MINT_BATCH_SIZE = 16;

    /// @dev Once the first entry crosses RAFFLE_SUPPLY cumulative entries, the raffle
    ///      closes exactly this long afterwards (the announced closing rule).
    uint256 public constant CLOSE_DELAY = 24 hours;

    /// @dev After this delay past claims opening the owner may sweep unclaimed refunds.
    ///      NFT claim rights never expire; only the refund reserve is sweepable.
    uint256 public constant UNCLAIMED_SWEEP_DELAY = 180 days;

    /// @dev If claims have not opened this long after the raffle end, settlement has
    ///      failed: `openClaims` is permanently blocked and every entrant can pull
    ///      their full deposit back via `emergencyRefund`.
    uint256 public constant SETTLEMENT_TIMEOUT = 90 days;

    /// @dev A pending VRF request can only be replaced after this cooldown. Prevents the
    ///      owner from front-running an incoming fulfillment to discard an unfavorable
    ///      seed (Chainlink security consideration: never allow re-requesting randomness)
    ///      while still permitting recovery from genuinely stalled requests.
    uint256 public constant SEED_RETRY_COOLDOWN = 24 hours;

    /// @dev Royalty ceiling (basis points) for the constructor and `setDefaultRoyalty`.
    uint96 public constant MAX_ROYALTY_BPS = 1_000;

    /// @dev Aux bit 63 marks the refund as claimed; bits 0..62 count NFTs already minted
    ///      for the wallet's raffle entitlement. Lives in ERC721A's per-address aux word,
    ///      so claim bookkeeping costs no extra storage slot.
    uint64 private constant _AUX_REFUND_CLAIMED = 1 << 63;
    uint64 private constant _AUX_NFT_MASK = _AUX_REFUND_CLAIMED - 1;

    // ─── Sale state ────────────────────────────────────────────────────────

    /// @notice Wei committed per raffle entry. Nonzero always; fixed once the first
    ///         entry is placed.
    uint256 public entryPrice;
    address public treasury;

    uint64 public raffleStart;
    uint64 public raffleEnd;
    /// @notice Timestamp at which cumulative entries first crossed `RAFFLE_SUPPLY`
    ///         (zero if never). Crossing fixes `raffleEnd` at exactly +24h.
    uint64 public thresholdReachedAt;

    uint256 public totalEntries;
    mapping(address wallet => uint256 entries) public entriesOf;

    // ─── Transfer validator (minimal ICreatorToken surface) ───────────────

    /// @dev Consulted on every non-mint transfer once set. Never granted approvals and
    ///      never exempt from validation itself — see the contract-level docs.
    address private _transferValidator;

    // ─── VRF state ─────────────────────────────────────────────────────────

    /// @dev The inherited `setCoordinator` (not virtual, so not removable) would let the
    ///      owner point `s_vrfCoordinator` at an arbitrary contract and inject a chosen
    ///      seed. Pinning the deploy-time coordinator and checking it on both request and
    ///      fulfillment guarantees the seed can only ever come from the real coordinator.
    address public immutable PINNED_VRF_COORDINATOR;

    uint256 public vrfSubscriptionId;
    bytes32 public vrfKeyHash;
    uint32 public vrfCallbackGasLimit = 150_000;
    uint16 public vrfRequestConfirmations = 5;
    bool public vrfPayWithNative;

    uint256 public vrfRequestId;
    uint64 public seedRequestedAt;
    /// @notice VRF-provided raffle seed; nonzero once fulfilled.
    uint256 public raffleSeed;

    uint256 public revealVrfRequestId;
    uint64 public revealSeedRequestedAt;
    /// @notice VRF-provided reveal seed (drives the token→metadata offset); nonzero once
    ///         fulfilled. Independent of `raffleSeed` so the draw never waits on the art.
    uint256 public revealSeed;

    // ─── Allocation / claims ───────────────────────────────────────────────

    /// @notice Hash committing the final metadata ordering, set whenever the art is ready —
    ///         before the REVEAL seed request (not the raffle one), so the ordering is fixed
    ///         while the reveal offset is still unknown. Holders verify reveal integrity
    ///         against it.
    bytes32 public provenanceHash;

    /// @notice Hash committing the exact allocator (algorithm code + parameters) that turns
    ///         (on-chain entries, raffleSeed) into `allocationRoot`. Like `provenanceHash`
    ///         it must be set before the seed is requested, so the algorithm is fixed while
    ///         the seed is still unknown. Without this the posted root is only verifiable
    ///         against a reference the team could pick after seeing the seed.
    bytes32 public allocatorHash;

    /// @notice Merkle root of keccak256(keccak256(abi.encode(wallet, nftAmount, refundWei))).
    bytes32 public allocationRoot;
    /// @notice Sum of all refundWei leaves in `allocationRoot`.
    uint256 public allocationRefundTotal;

    bool public claimsOpen;
    uint64 public claimsOpenedAt;
    /// @notice ETH still reserved for unclaimed refunds; never withdrawable by treasury.
    uint256 public refundReserve;
    /// @notice True once `sweepUnclaimed` has run: refund legs are expired forever,
    ///         NFT claims continue unaffected.
    bool public refundsSwept;

    // ─── Mint accounting ───────────────────────────────────────────────────

    uint256 public presaleMinted;
    uint256 public teamMinted;
    uint256 public raffleClaimed;

    // ─── Metadata ──────────────────────────────────────────────────────────

    string public unrevealedURI;
    string private _baseTokenURI;
    bool public metadataFrozen;

    // ─── Errors ────────────────────────────────────────────────────────────

    // Note: ZeroAddress() is inherited from VRFConsumerBaseV2Plus.
    error InvalidQuantity();
    error LengthMismatch();
    error IncorrectPayment();
    error ZeroEntryPrice();
    error RaffleNotOpen();
    error RaffleNotEnded();
    error RaffleConfigLocked();
    error EntriesExist();
    error SeedAlreadySet();
    error SeedNotSet();
    error SeedRequestPending();
    error RevealSeedAlreadySet();
    error RevealSeedNotSet();
    error RevealSeedRequestPending();
    error CoordinatorChanged();
    error ProvenanceNotSet();
    error ProvenanceLocked();
    error AllocatorNotSet();
    error AllocatorLocked();
    error AllocationNotSet();
    error InvalidAllocation();
    error ClaimsAlreadyOpen();
    error ClaimsNotOpen();
    error AlreadyClaimed();
    error InvalidProof();
    error NothingToClaim();
    error SupplyExceeded();
    error PresaleClosed();
    error TradingLocked();
    error NothingToWithdraw();
    error SweepNotReady();
    error RefundsExpired();
    error SettlementNotExpired();
    error SettlementExpired();
    error MetadataFrozen();
    error EthTransferFailed();
    error InvalidTransferValidator();
    error RoyaltyTooHigh();

    // ─── Events ────────────────────────────────────────────────────────────

    event RaffleConfigured(uint64 startTime, uint64 endTime, uint256 entryPrice);
    event RaffleEntered(
        address indexed wallet, uint256 quantity, uint256 walletEntries, uint256 totalEntries
    );
    event RaffleThresholdReached(uint64 reachedAt, uint64 raffleEnd);
    event PresaleAirdropped(address indexed to, uint256 quantity, uint256 firstTokenId);
    event TeamMinted(address indexed to, uint256 quantity);
    event ProvenanceCommitted(bytes32 provenanceHash);
    event AllocatorCommitted(bytes32 allocatorHash);
    event VrfConfigUpdated(
        uint256 subscriptionId,
        bytes32 keyHash,
        uint32 callbackGasLimit,
        uint16 requestConfirmations,
        bool payWithNative
    );
    event RaffleSeedRequested(uint256 indexed requestId);
    event RaffleSeedFulfilled(uint256 indexed requestId, uint256 seed);
    event RevealSeedRequested(uint256 indexed requestId);
    event RevealSeedFulfilled(uint256 indexed requestId, uint256 seed);
    event AllocationPosted(bytes32 indexed root, uint256 refundTotal, uint256 seed);
    event ClaimsOpened(uint64 openedAt, bytes32 root, uint256 refundReserve);
    event NftsClaimed(address indexed wallet, uint256 minted, uint256 totalMinted, uint256 entitled);
    event RefundClaimed(address indexed wallet, address indexed to, uint256 refundWei);
    event EmergencyRefunded(address indexed wallet, address indexed to, uint256 entries, uint256 amount);
    event ProceedsWithdrawn(address indexed to, uint256 amount);
    event UnclaimedSwept(address indexed to, uint256 amount);
    event TreasuryUpdated(address treasury);
    event MetadataUpdated(string unrevealedURI, string baseURI);
    event MetadataFrozenForever();
    /// @dev ERC-4906, so marketplaces invalidate cached metadata on reveal swaps.
    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);

    constructor(
        uint256 entryPrice_,
        address treasury_,
        address vrfCoordinator_,
        uint256 vrfSubscriptionId_,
        bytes32 vrfKeyHash_,
        address royaltyReceiver_,
        uint96 royaltyFeeNumerator_
    )
        ERC721A("Blokyz", "BLOKYZ")
        BasicRoyalties(royaltyReceiver_, royaltyFeeNumerator_)
        VRFConsumerBaseV2Plus(vrfCoordinator_)
    {
        if (entryPrice_ == 0) revert ZeroEntryPrice();
        if (treasury_ == address(0)) revert ZeroAddress();
        if (royaltyFeeNumerator_ > MAX_ROYALTY_BPS) revert RoyaltyTooHigh();
        PINNED_VRF_COORDINATOR = vrfCoordinator_;
        entryPrice = entryPrice_;
        treasury = treasury_;
        vrfSubscriptionId = vrfSubscriptionId_;
        vrfKeyHash = vrfKeyHash_;
        emit VrfConfigUpdated(
            vrfSubscriptionId_, vrfKeyHash_, vrfCallbackGasLimit, vrfRequestConfirmations, false
        );
    }

    // ─── Views ─────────────────────────────────────────────────────────────

    /// @dev First token id. ERC721A defaults to 0; the collection is 1-indexed.
    ///      `totalSupply()` comes from ERC721A and equals presaleMinted + teamMinted +
    ///      raffleClaimed (nothing in this contract burns).
    function _startTokenId() internal pure override returns (uint256) {
        return 1;
    }

    /// @notice Subscription in basis points: 10_000 = exactly 100% subscribed.
    function subscriptionBps() external view returns (uint256) {
        return totalEntries * 10_000 / RAFFLE_SUPPLY;
    }

    /// @notice NFTs already minted against `wallet`'s raffle entitlement (packed in
    ///         ERC721A aux storage — claims are incremental, see `claimNfts`).
    function nftsClaimedOf(address wallet) public view returns (uint256) {
        return _getAux(wallet) & _AUX_NFT_MASK;
    }

    /// @notice Whether `wallet` has already taken its refund leg.
    function refundClaimedOf(address wallet) public view returns (bool) {
        return _getAux(wallet) & _AUX_REFUND_CLAIMED != 0;
    }

    /// @notice Timestamp after which settlement is considered failed: `openClaims` is
    ///         blocked and `emergencyRefund` opens. Zero while the raffle is unconfigured.
    function settlementDeadline() public view returns (uint256) {
        return raffleEnd == 0 ? 0 : uint256(raffleEnd) + SETTLEMENT_TIMEOUT;
    }

    /// @notice Leaf digest for the allocation Merkle tree (OZ double-hash format).
    function allocationLeaf(address wallet, uint256 nftAmount, uint256 refundWei)
        public
        pure
        returns (bytes32)
    {
        return keccak256(bytes.concat(keccak256(abi.encode(wallet, nftAmount, refundWei))));
    }

    // ─── Raffle entries ────────────────────────────────────────────────────

    /// @notice Commit `quantity` paid raffle entries. Uncapped; min 1 per tx. The entry
    ///         that first pushes cumulative entries to `RAFFLE_SUPPLY` starts the
    ///         announced 24-hour closing clock: `raffleEnd` snaps to now + 24h and can
    ///         never move again.
    function enterRaffle(uint256 quantity) external payable whenNotPaused {
        if (quantity == 0) revert InvalidQuantity();
        if (raffleStart == 0 || block.timestamp < raffleStart || block.timestamp >= raffleEnd) {
            revert RaffleNotOpen();
        }
        // Checked multiplication (overflow-safe); entryPrice is always nonzero, so the
        // sums below are bounded by total ETH paid in and can be unchecked.
        if (msg.value != quantity * entryPrice) revert IncorrectPayment();

        uint256 walletEntries;
        uint256 newTotal;
        unchecked {
            walletEntries = entriesOf[msg.sender] + quantity;
            newTotal = totalEntries + quantity;
        }
        entriesOf[msg.sender] = walletEntries;
        totalEntries = newTotal;
        emit RaffleEntered(msg.sender, quantity, walletEntries, newTotal);

        if (thresholdReachedAt == 0 && newTotal >= RAFFLE_SUPPLY) {
            uint64 reachedAt = uint64(block.timestamp);
            uint64 closeAt = uint64(block.timestamp + CLOSE_DELAY);
            thresholdReachedAt = reachedAt;
            raffleEnd = closeAt;
            emit RaffleThresholdReached(reachedAt, closeAt);
        }
    }

    // ─── Presale & team ────────────────────────────────────────────────────

    /// @notice Airdrop presale tokens, taking the first ids in the collection. Locked until
    ///         claims open. Ids are sequential, so the presale must be fully airdropped before
    ///         any team or raffle mint — otherwise the presale block would not be contiguous.
    function airdropPresale(address[] calldata recipients, uint256[] calldata quantities)
        external
        onlyOwner
    {
        if (recipients.length != quantities.length) revert LengthMismatch();
        if (teamMinted != 0 || raffleClaimed != 0) revert PresaleClosed();

        uint256 minted = presaleMinted;
        for (uint256 i = 0; i < recipients.length;) {
            address to = recipients[i];
            uint256 quantity = quantities[i];
            if (to == address(0)) revert ZeroAddress();
            if (quantity == 0) revert InvalidQuantity();
            minted += quantity;
            if (minted > PRESALE_MAX_SUPPLY) revert SupplyExceeded();

            emit PresaleAirdropped(to, quantity, _nextTokenId());
            _mintBatched(to, quantity);
            unchecked {
                ++i;
            }
        }
        presaleMinted = minted;
    }

    /// @notice Mint from the guaranteed team allocation.
    function mintTeam(address to, uint256 quantity) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (quantity == 0) revert InvalidQuantity();
        uint256 newTeamMinted = teamMinted + quantity;
        if (newTeamMinted > TEAM_ALLOCATION) revert SupplyExceeded();

        teamMinted = newTeamMinted;
        _mintBatched(to, quantity);
        emit TeamMinted(to, quantity);
    }

    // ─── VRF resolution ────────────────────────────────────────────────────

    /// @notice Request the raffle seed from Chainlink VRF. Only after the entry window
    ///         closes and the allocator hash is committed. The metadata provenance hash
    ///         is deliberately NOT required — the reveal runs on its own seed
    ///         (`requestRevealSeed`), so unfinished art can never delay the draw.
    ///         A stalled request can be replaced only after `SEED_RETRY_COOLDOWN`, so an
    ///         incoming fulfillment can never be discarded; only the latest request is
    ///         honored, once.
    function requestRaffleSeed() external onlyOwner returns (uint256 requestId) {
        if (raffleEnd == 0 || block.timestamp < raffleEnd) revert RaffleNotEnded();
        if (raffleSeed != 0) revert SeedAlreadySet();
        if (allocatorHash == bytes32(0)) revert AllocatorNotSet();
        if (vrfRequestId != 0 && block.timestamp < uint256(seedRequestedAt) + SEED_RETRY_COOLDOWN) {
            revert SeedRequestPending();
        }
        seedRequestedAt = uint64(block.timestamp);
        requestId = _requestRandomWord();
        vrfRequestId = requestId;
        emit RaffleSeedRequested(requestId);
    }

    /// @notice Request the reveal seed from Chainlink VRF — the raffle draw's independent
    ///         twin for metadata fairness. Callable whenever the art is final: the
    ///         provenance hash (metadata ordering) must already be committed, so the
    ///         token→metadata offset derived from this seed is provably outside anyone's
    ///         control. No coupling to the raffle seed in either direction. Same
    ///         stalled-request replacement rule as the raffle request.
    function requestRevealSeed() external onlyOwner returns (uint256 requestId) {
        if (provenanceHash == bytes32(0)) revert ProvenanceNotSet();
        if (revealSeed != 0) revert RevealSeedAlreadySet();
        if (
            revealVrfRequestId != 0
                && block.timestamp < uint256(revealSeedRequestedAt) + SEED_RETRY_COOLDOWN
        ) {
            revert RevealSeedRequestPending();
        }
        revealSeedRequestedAt = uint64(block.timestamp);
        requestId = _requestRandomWord();
        revealVrfRequestId = requestId;
        emit RevealSeedRequested(requestId);
    }

    /// @dev Shared VRF request for both seeds; coordinator request ids are globally
    ///      unique, so the two flows can never collide in `fulfillRandomWords`.
    function _requestRandomWord() private returns (uint256 requestId) {
        if (address(s_vrfCoordinator) != PINNED_VRF_COORDINATOR) revert CoordinatorChanged();
        requestId = s_vrfCoordinator.requestRandomWords(
            VRFV2PlusClient.RandomWordsRequest({
                keyHash: vrfKeyHash,
                subId: vrfSubscriptionId,
                requestConfirmations: vrfRequestConfirmations,
                callbackGasLimit: vrfCallbackGasLimit,
                numWords: 1,
                extraArgs: VRFV2PlusClient._argsToBytes(
                    VRFV2PlusClient.ExtraArgsV1({nativePayment: vrfPayWithNative})
                )
            })
        );
    }

    /// @dev Stores whichever seed the request id belongs to. Never reverts on
    ///      stale/duplicate fulfillments (VRF best practice).
    function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords)
        internal
        override
    {
        // Caller is s_vrfCoordinator (checked in rawFulfillRandomWords); only accept the
        // fulfillment if that is still the pinned, genuine coordinator.
        if (address(s_vrfCoordinator) != PINNED_VRF_COORDINATOR) return;
        uint256 seed = randomWords[0];
        if (seed == 0) seed = 1;
        if (requestId == vrfRequestId && raffleSeed == 0) {
            raffleSeed = seed;
            emit RaffleSeedFulfilled(requestId, seed);
        } else if (requestId == revealVrfRequestId && revealSeed == 0) {
            revealSeed = seed;
            emit RevealSeedFulfilled(requestId, seed);
        }
    }

    // ─── Allocation & claims ───────────────────────────────────────────────

    /// @notice Post the allocation Merkle root computed by the pre-committed allocator
    ///         (`allocatorHash`) from (on-chain entries, raffleSeed). Re-postable until
    ///         `openClaims()` freezes it, so a root that does not match the committed
    ///         allocator can be called out and corrected before claims begin.
    /// @param root        Merkle root over `allocationLeaf(wallet, nftAmount, refundWei)`.
    /// @param refundTotal Sum of every refundWei leaf; reserved for claimants.
    function setAllocation(bytes32 root, uint256 refundTotal) external onlyOwner {
        if (raffleSeed == 0) revert SeedNotSet();
        if (claimsOpen) revert ClaimsAlreadyOpen();
        if (root == bytes32(0)) revert InvalidAllocation();
        if (refundTotal > totalEntries * entryPrice) revert InvalidAllocation();

        allocationRoot = root;
        allocationRefundTotal = refundTotal;
        emit AllocationPosted(root, refundTotal, raffleSeed);
    }

    /// @notice Freeze the allocation, open the claim window, and unlock trading
    ///         (presale + team tokens included). Blocked forever once the settlement
    ///         deadline has passed — at that point `emergencyRefund` is the only path.
    function openClaims() external onlyOwner {
        if (allocationRoot == bytes32(0)) revert AllocationNotSet();
        if (claimsOpen) revert ClaimsAlreadyOpen();
        if (totalEntries != 0 && block.timestamp >= settlementDeadline()) {
            revert SettlementExpired();
        }

        claimsOpen = true;
        claimsOpenedAt = uint64(block.timestamp);
        refundReserve = allocationRefundTotal;
        emit ClaimsOpened(claimsOpenedAt, allocationRoot, allocationRefundTotal);
    }

    /// @notice Convenience pull-claim: mints every not-yet-minted NFT of the entitlement
    ///         and sends the refund to the caller, in one transaction. Equivalent to
    ///         `claimNfts(..., type(uint256).max)` + `claimRefund(..., msg.sender)`;
    ///         use those directly for chunked mints or a different refund recipient.
    function claim(uint256 nftAmount, uint256 refundWei, bytes32[] calldata proof)
        external
        nonReentrant
    {
        _checkClaim(nftAmount, refundWei, proof);
        uint256 minted = _claimNfts(nftAmount, type(uint256).max);
        uint256 refunded = _claimRefund(refundWei, payable(msg.sender), false);
        if (minted == 0 && refunded == 0) revert NothingToClaim();
    }

    /// @notice Mint up to `maxMint` NFTs of the caller's entitlement. Callable repeatedly
    ///         until the full `nftAmount` is minted, so an entitlement of any size fits
    ///         under the mainnet per-transaction gas cap. Independent of the refund leg.
    function claimNfts(uint256 nftAmount, uint256 refundWei, bytes32[] calldata proof, uint256 maxMint)
        external
        nonReentrant
    {
        if (maxMint == 0) revert InvalidQuantity();
        _checkClaim(nftAmount, refundWei, proof);
        if (_claimNfts(nftAmount, maxMint) == 0) revert NothingToClaim();
    }

    /// @notice Send the caller's refund leg to `to` (any payable recipient the entitled
    ///         wallet chooses), once. Independent of the NFT leg, so a claimant that
    ///         cannot receive raw ETH can still mint and route its refund elsewhere.
    function claimRefund(uint256 nftAmount, uint256 refundWei, bytes32[] calldata proof, address to)
        external
        nonReentrant
    {
        if (to == address(0)) revert ZeroAddress();
        _checkClaim(nftAmount, refundWei, proof);
        _claimRefund(refundWei, payable(to), true);
    }

    /// @dev Common gates: claims open + the leaf (bound to msg.sender) verifies.
    function _checkClaim(uint256 nftAmount, uint256 refundWei, bytes32[] calldata proof)
        private
        view
    {
        if (!claimsOpen) revert ClaimsNotOpen();
        if (!MerkleProof.verifyCalldata(
                proof, allocationRoot, allocationLeaf(msg.sender, nftAmount, refundWei)
            )) revert InvalidProof();
    }

    /// @dev Mints min(maxMint, remaining entitlement) to msg.sender; returns the count.
    function _claimNfts(uint256 entitled, uint256 maxMint) private returns (uint256 toMint) {
        uint64 aux = _getAux(msg.sender);
        uint256 already = aux & _AUX_NFT_MASK;
        if (already >= entitled) return 0;

        uint256 remaining;
        unchecked {
            remaining = entitled - already;
        }
        toMint = maxMint < remaining ? maxMint : remaining;

        uint256 newRaffleClaimed = raffleClaimed + toMint;
        if (newRaffleClaimed > RAFFLE_SUPPLY) revert SupplyExceeded();
        raffleClaimed = newRaffleClaimed;
        // toMint <= RAFFLE_SUPPLY, so the packed counter can never touch the refund bit.
        _setAux(msg.sender, aux + uint64(toMint));

        emit NftsClaimed(msg.sender, toMint, already + toMint, entitled);
        _mintBatched(msg.sender, toMint);
    }

    /// @dev Pays the refund leg once. `strict` reverts on an impossible leg (already
    ///      claimed / zero / swept); non-strict (the combined `claim`) skips it so the
    ///      NFT leg can never be blocked by the refund leg.
    function _claimRefund(uint256 refundWei, address payable to, bool strict)
        private
        returns (uint256)
    {
        uint64 aux = _getAux(msg.sender);
        if (refundWei == 0) {
            if (strict) revert NothingToClaim();
            return 0;
        }
        if (aux & _AUX_REFUND_CLAIMED != 0) {
            if (strict) revert AlreadyClaimed();
            return 0;
        }
        if (refundsSwept) {
            if (strict) revert RefundsExpired();
            return 0;
        }

        _setAux(msg.sender, aux | _AUX_REFUND_CLAIMED);
        refundReserve -= refundWei; // checked: reverts if the allocation under-reserved
        emit RefundClaimed(msg.sender, to, refundWei);
        (bool ok,) = to.call{value: refundWei}("");
        if (!ok) revert EthTransferFailed();
        return refundWei;
    }

    // ─── Settlement failure recovery ───────────────────────────────────────

    /// @notice If claims never opened by `settlementDeadline()`, any entrant can pull
    ///         their full deposit (`entriesOf * entryPrice`) back, to any recipient
    ///         they choose. `openClaims` is permanently blocked past the same deadline,
    ///         so the two paths can never overlap.
    function emergencyRefund(address to) external nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (claimsOpen) revert ClaimsAlreadyOpen();
        uint256 deadline = settlementDeadline();
        if (deadline == 0 || block.timestamp < deadline) revert SettlementNotExpired();

        uint256 entries = entriesOf[msg.sender];
        if (entries == 0) revert NothingToClaim();
        entriesOf[msg.sender] = 0;
        uint256 amount = entries * entryPrice;

        emit EmergencyRefunded(msg.sender, to, entries, amount);
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert EthTransferFailed();
    }

    // ─── Treasury ──────────────────────────────────────────────────────────

    /// @notice Withdraw raffle proceeds, always leaving the outstanding refund reserve.
    function withdrawProceeds() external onlyOwner nonReentrant {
        if (!claimsOpen) revert ClaimsNotOpen();
        uint256 amount = address(this).balance - refundReserve;
        if (amount == 0) revert NothingToWithdraw();

        (bool ok,) = treasury.call{value: amount}("");
        if (!ok) revert EthTransferFailed();
        emit ProceedsWithdrawn(treasury, amount);
    }

    /// @notice After a 180-day grace period, sweep refunds that were never claimed.
    ///         Expires refund legs only — NFT entitlements remain claimable forever.
    function sweepUnclaimed() external onlyOwner nonReentrant {
        if (!claimsOpen || block.timestamp < uint256(claimsOpenedAt) + UNCLAIMED_SWEEP_DELAY) {
            revert SweepNotReady();
        }
        uint256 amount = address(this).balance;
        if (amount == 0) revert NothingToWithdraw();

        refundsSwept = true;
        refundReserve = 0;
        (bool ok,) = treasury.call{value: amount}("");
        if (!ok) revert EthTransferFailed();
        emit UnclaimedSwept(treasury, amount);
    }

    // ─── Transfer validator (ICreatorToken) ────────────────────────────────

    /// @inheritdoc ICreatorToken
    function getTransferValidator() external view returns (address validator) {
        return _transferValidator;
    }

    /// @inheritdoc ICreatorToken
    function getTransferValidationFunction()
        external
        pure
        returns (bytes4 functionSignature, bool isViewFunction)
    {
        functionSignature = bytes4(keccak256("validateTransfer(address,address,address,uint256)"));
        isViewFunction = true;
    }

    /// @notice Set the transfer validator. Zero disables validation. The validator is
    ///         only ever *consulted* — it receives no operator approval and no exemption
    ///         from validation, so it can veto transfers but never move tokens itself.
    function setTransferValidator(address validator) external onlyOwner {
        if (validator != address(0) && validator.code.length == 0) {
            revert InvalidTransferValidator();
        }
        emit TransferValidatorUpdated(_transferValidator, validator);
        _transferValidator = validator;
    }

    // ─── Admin config ──────────────────────────────────────────────────────

    /// @notice Set the raffle entry window. Locked forever once the first entry exists —
    ///         the only end-time change after that is the automatic 24h threshold close.
    ///         `endTime` is the backstop for a raffle that never reaches the threshold.
    function configureRaffle(uint64 startTime, uint64 endTime) external onlyOwner {
        if (vrfRequestId != 0 || totalEntries != 0) revert RaffleConfigLocked();
        if (startTime == 0 || startTime >= endTime) revert RaffleConfigLocked();
        raffleStart = startTime;
        raffleEnd = endTime;
        emit RaffleConfigured(startTime, endTime, entryPrice);
    }

    /// @notice Update the entry price; only before any entries exist, never zero.
    function setEntryPrice(uint256 newPrice) external onlyOwner {
        if (newPrice == 0) revert ZeroEntryPrice();
        if (totalEntries != 0) revert EntriesExist();
        entryPrice = newPrice;
        emit RaffleConfigured(raffleStart, raffleEnd, newPrice);
    }

    /// @notice Commit the metadata provenance hash whenever the art is final — fully
    ///         decoupled from the raffle draw. Locked once the REVEAL seed is requested,
    ///         so the ordering is pinned while the reveal offset is still unknown.
    function setProvenanceHash(bytes32 hash) external onlyOwner {
        if (revealVrfRequestId != 0) revert ProvenanceLocked();
        provenanceHash = hash;
        emit ProvenanceCommitted(hash);
    }

    /// @notice Commit the allocator hash: keccak256 over the published allocator manifest
    ///         (algorithm code + parameters + spec, see `scripts/allocator/ALLOCATOR.md`).
    ///         Locked once the seed is requested, so the algorithm that maps entries and
    ///         seed to `allocationRoot` is fixed before the seed exists.
    function setAllocatorHash(bytes32 hash) external onlyOwner {
        if (vrfRequestId != 0) revert AllocatorLocked();
        allocatorHash = hash;
        emit AllocatorCommitted(hash);
    }

    /// @notice Rotate VRF plumbing (subscription, key hash, gas, payment mode). Allowed
    ///         until BOTH seeds have landed: the reveal request may fire months after the
    ///         draw, and Chainlink can retire a gas lane in between. Config can never
    ///         change a landed seed — fulfillments bind to the pinned coordinator and the
    ///         recorded request id.
    function setVrfConfig(
        uint256 subscriptionId,
        bytes32 keyHash,
        uint32 callbackGasLimit,
        uint16 requestConfirmations,
        bool payWithNative
    ) external onlyOwner {
        if (raffleSeed != 0 && revealSeed != 0) revert SeedAlreadySet();
        vrfSubscriptionId = subscriptionId;
        vrfKeyHash = keyHash;
        vrfCallbackGasLimit = callbackGasLimit;
        vrfRequestConfirmations = requestConfirmations;
        vrfPayWithNative = payWithNative;
        emit VrfConfigUpdated(
            subscriptionId, keyHash, callbackGasLimit, requestConfirmations, payWithNative
        );
    }

    function setTreasury(address treasury_) external onlyOwner {
        if (treasury_ == address(0)) revert ZeroAddress();
        treasury = treasury_;
        emit TreasuryUpdated(treasury_);
    }

    /// @notice Update royalties, capped at `MAX_ROYALTY_BPS` (10%).
    function setDefaultRoyalty(address receiver, uint96 feeNumerator) external onlyOwner {
        if (feeNumerator > MAX_ROYALTY_BPS) revert RoyaltyTooHigh();
        _setDefaultRoyalty(receiver, feeNumerator);
    }

    /// @notice Update the placeholder and/or final base URI. The unrevealed URI is free to
    ///         change any time (pre-reveal box states); a NONEMPTY base URI is the full
    ///         reveal and is refused until the reveal seed has landed — the token→metadata
    ///         offset must come from a VRF word that postdates the committed provenance
    ///         ordering, or the reveal is not provably fair.
    function setMetadata(string calldata unrevealedURI_, string calldata baseURI_)
        external
        onlyOwner
    {
        if (metadataFrozen) revert MetadataFrozen();
        if (bytes(baseURI_).length != 0 && revealSeed == 0) revert RevealSeedNotSet();
        unrevealedURI = unrevealedURI_;
        _baseTokenURI = baseURI_;
        emit MetadataUpdated(unrevealedURI_, baseURI_);
        emit BatchMetadataUpdate(_startTokenId(), type(uint256).max);
    }

    /// @notice Permanently freeze metadata after the full reveal.
    function freezeMetadata() external onlyOwner {
        metadataFrozen = true;
        emit MetadataFrozenForever();
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // ─── Metadata ──────────────────────────────────────────────────────────

    /// @dev Identical placeholder for every token pre-reveal (no rarity leak); reveal
    ///      states (box art at T+3d, full art at T+7d) are base URI swaps verified
    ///      against `provenanceHash`.
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        if (!_exists(tokenId)) revert URIQueryForNonexistentToken();
        string memory base = _baseTokenURI;
        if (bytes(base).length == 0) return unrevealedURI;
        return string.concat(base, tokenId.toString(), ".json");
    }

    // ─── Internals ─────────────────────────────────────────────────────────

    /// @dev ERC721A batch mint, split into `MINT_BATCH_SIZE` chunks so no token is ever more
    ///      than one chunk away from an initialized ownership slot.
    function _mintBatched(address to, uint256 quantity) internal {
        uint256 remaining = quantity;
        while (remaining > MINT_BATCH_SIZE) {
            _mint(to, MINT_BATCH_SIZE);
            unchecked {
                remaining -= MINT_BATCH_SIZE;
            }
        }
        _mint(to, remaining);
    }

    /// @dev All tokens (presale, team, raffle) are transfer-locked until claims open;
    ///      mints are always allowed. Once unlocked, every real transfer — regardless of
    ///      who the caller is — must pass the configured validator. There is no
    ///      validator-caller exemption and the validator holds no approvals, so it can
    ///      only veto, never confiscate.
    function _beforeTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal virtual override {
        if (from == address(0)) return; // mints (nothing here burns)
        if (!claimsOpen) revert TradingLocked();

        address validator = _transferValidator;
        if (validator != address(0)) {
            for (uint256 i = 0; i < quantity;) {
                ITransferValidator(validator).validateTransfer(
                    msg.sender, from, to, startTokenId + i
                );
                unchecked {
                    ++i;
                }
            }
        }
    }

    /// @dev ERC721A implements ERC165 itself rather than inheriting OpenZeppelin's, so the
    ///      two branches do not share a tail; both roots are queried explicitly, plus the
    ///      creator-token and ERC-4906 ids this contract implements directly.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721A, ERC2981)
        returns (bool)
    {
        return ERC721A.supportsInterface(interfaceId) || ERC2981.supportsInterface(interfaceId)
            || interfaceId == type(ICreatorToken).interfaceId || interfaceId == bytes4(0x49064906);
    }
}
