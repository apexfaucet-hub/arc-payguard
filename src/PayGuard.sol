// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title PayGuard: USDC on Arc that refuses to pay a poisoned or unverified address.
/// @notice An agent asks APEX arc-payee-check for a verdict on the payee (EIP-712, signed by ATTESTER), then calls pay().
///         The payment happens only if the verdict is NO_MATCH_IN_INDEX (0), unexpired, bound to the calling wallet and the payee,
///         within its maxAmount, and unused. USDC moves straight from msg.sender to the payee in the same transaction.
/// @dev    Holds no funds, has no owner, no upgrade, no admin. Only msg.sender's own allowance can ever be spent, and only to the
///         payee the attester signed for: a third party cannot use anyone else's approval or verdict.
contract PayGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant VERDICT_TYPEHASH = keccak256(
        "PayeeVerdict(address payer,address payee,uint256 maxAmount,uint8 verdict,uint32 reasons,uint64 indexedToBlock,uint64 issuedAt,uint64 expiresAt,bytes32 evidenceHash)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;
    address public immutable ATTESTER;
    IERC20 public immutable USDC;
    mapping(bytes32 => bool) public used;

    struct Verdict {
        address payer;
        address payee;
        uint256 maxAmount;
        uint8 verdict;
        uint32 reasons;
        uint64 indexedToBlock;
        uint64 issuedAt;
        uint64 expiresAt;
        bytes32 evidenceHash;
    }

    event GuardedPayment(address indexed payer, address indexed payee, uint256 amount, bytes32 indexed verdictDigest, string memo);

    error ZeroAddress();
    error ZeroAmount();
    error NotClean(uint8 verdict);
    error Expired();
    error WrongPayer();
    error NoAmountCap();
    error OverMax();
    error BadSignature();
    error Replayed();

    constructor(address attester, address usdc) {
        if (attester == address(0) || usdc == address(0)) revert ZeroAddress();
        ATTESTER = attester;
        USDC = IERC20(usdc);
        // Same domain the API signs with: name, version, chainId; no verifyingContract (the verdict is not tied to one contract).
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId)"), keccak256("APEX PayeeCheck"), keccak256("1"), block.chainid)
        );
    }

    function digest(Verdict calldata v) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(VERDICT_TYPEHASH, v.payer, v.payee, v.maxAmount, v.verdict, v.reasons, v.indexedToBlock, v.issuedAt, v.expiresAt, v.evidenceHash))
            )
        );
    }

    /// @param v the verdict exactly as arc-payee-check returned it (attestation.message)
    /// @param sig attestation.signature
    /// @param amount USDC in 6-decimal units, at most v.maxAmount
    function pay(Verdict calldata v, bytes calldata sig, uint256 amount, string calldata memo) external {
        if (amount == 0) revert ZeroAmount();
        if (v.verdict != 0) revert NotClean(v.verdict);
        if (block.timestamp > v.expiresAt) revert Expired();
        if (v.payer != msg.sender) revert WrongPayer();
        if (v.maxAmount == 0) revert NoAmountCap();
        if (amount > v.maxAmount) revert OverMax();
        bytes32 d = digest(v);
        if (ECDSA.recover(d, sig) != ATTESTER) revert BadSignature();
        if (used[d]) revert Replayed();
        used[d] = true;
        emit GuardedPayment(msg.sender, v.payee, amount, d, memo);
        USDC.safeTransferFrom(msg.sender, v.payee, amount);
    }
}
