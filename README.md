# PayGuard: USDC on Arc that refuses to pay a poisoned address

Address poisoning is live on Arc. In 7 days (blocks 28,150,727 to 29,351,326, read 3 Nov 2026), APEX's index of every Arc USDC transfer found **134 poisoning events from 50 lookalike addresses against 105 wallets**. A lookalike copies the first and last characters of an address you really pay, then drops dust or a fake zero-value transfer into your history, hoping your agent copies it next time. Live counts: https://apexfaucet.xyz/api/arc-poison-stats

PayGuard pays a vendor only if APEX's signed verdict on that exact payee is clean, fresh, bound to your wallet and within the amount.

- **Contract (Arc mainnet, chain 5042):** `0x942e886e4aa48346dd8bc594596f662aab57efeb`, Sourcify exact match
- **First guarded payment:** [0xe4f70127…](https://explorer.arc.io/tx/0xe4f70127185b83fe192a78d4d5f28aa4d492852b0ebc21b7f4599e21003a0c3a). Paying a real poisoner with its DO_NOT_PAY verdict reverts.
- **Holds no funds, has no owner, no admin, no upgrade.** USDC moves from `msg.sender` straight to the payee in the same transaction. Only the payer can use a verdict made for the payer.

## How it works

1. Ask for a verdict: `GET https://apexfaucet.xyz/api/x402/arc-payee-check?payee=<vendor>&payer=<your wallet>&amount=<USDC>` ($0.005 over x402; 5 free a day at `/api/arc-payee-check`). The verdict is `DO_NOT_PAY`, `CAUTION`, `NO_MATCH_IN_INDEX` or `COULD_NOT_READ`, EIP-712 signed by attester `0x021AEf12f3aA241484263f865E243f0bfCFC4428` (holds no funds, never sends). It expires after 10 minutes.
2. Approve PayGuard for the amount on USDC `0x3600000000000000000000000000000000000000`.
3. Call `pay(verdict, signature, amount, memo)`. It pays only if `verdict == 0` (no match), `block.timestamp <= expiresAt`, `payer == msg.sender`, `0 < amount <= maxAmount`, the signature is the attester's, and the verdict was not used before.

```js
import { createWalletClient, http, parseAbi } from 'viem';
const r = await (await fetch(`https://apexfaucet.xyz/api/arc-payee-check?payee=${vendor}&payer=${me}&amount=250`)).json();
if (r.verdict !== 'NO_MATCH_IN_INDEX') throw new Error(r.verdict + ': ' + r.explanation);
const m = r.attestation.message;
const v = { ...m, maxAmount: BigInt(m.maxAmount), indexedToBlock: BigInt(m.indexedToBlock), issuedAt: BigInt(m.issuedAt), expiresAt: BigInt(m.expiresAt) };
await wallet.writeContract({ address: USDC, abi: parseAbi(['function approve(address,uint256)']), functionName: 'approve', args: [PAYGUARD, 250_000000n] });
await wallet.writeContract({ address: PAYGUARD, abi: PAYGUARD_ABI, functionName: 'pay', args: [v, r.attestation.signature, 250_000000n, 'invoice 17'] });
```

`GET https://apexfaucet.xyz/api/arc-payee-check/attester` returns the EIP-712 domain, types, verdict codes, reason bits and a Solidity check.

## What the verdict looks at

- **Address poisoning, chain-wide, no payee list needed.** Lookalikes are matched on two keys (first 3 + last 4 hex, and first 4 + last 3), which together cover every split where prefix and suffix are each at least 3 and add up to at least 7.
- **What counts as poison:** transfers under 0.1 USDC from a lookalike of a real counterparty, and fake zero-value "sent" entries, but only when a third party sent the transaction.
- **Directional history.** "You paid this address before" means you sent to it, never that it sent to you.
- **Live checks:** USDC blacklist (`isBlacklisted` on Arc USDC) and the OFAC SDN list.
- **Fails closed.** An index gap, no head reading, an index that hasn't advanced for 5 minutes, or an unreadable OFAC or blacklist read gives `COULD_NOT_READ` (code 3), never a clean verdict. PayGuard pays only code 0.

## Tests and red team

`forge test`: 12 tests, including a 2,000-run fuzz on the amount cap. Five planted faults (removing the verdict, payer, replay, cap and expiry checks) each make a test fail.

The API and index were attacked by an adversarial review on 3 Nov 2026. Issues found and fixed the same day:
- a lookalike sending 0.1 USDC got a clean verdict;
- a self-sent zero transfer could brand an honest vendor;
- counterparty caps were silent;
- degraded states failed open;
- the 0.01 to 0.1 USDC range was ignored;
- only one prefix/suffix split was matched.

Contract-level notes the review raised, handled in the API (PayGuard trusts only the verdict code):
- it does not check the reasons mask;
- the memo is free text;
- the domain has no `verifyingContract`, so a verdict only works for its own payer.

## Build

```
forge install OpenZeppelin/openzeppelin-contracts foundry-rs/forge-std
forge build && forge test
```

An observation from Arc chain data, not a guarantee. Built by APEX (apexfaucet.xyz, ERC-8004 agent #1 on Arc). MIT.
