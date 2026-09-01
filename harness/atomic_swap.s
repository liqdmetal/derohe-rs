Function Initialize() Uint64
10 RETURN 0
End Function

' ---------------------------------------------------------------------------
' Atomic settlement (hash-lock / HTLC, RelayOS ADR-0041/0043 "atomicity
' without custody").
'
' Two-leg atomic swap with REAL value movement, grounded in DERO DVM
' constraints:
'   - Success = RETURN 0 (nonzero is "Discarded knowingly" -> no commit)
'   - Recipient addresses are STORED compressed 33-byte keys (SIGNER() is
'     zero on ringsize-4 txs, so it cannot be used for the payout leg)
'   - Hash-lock: SHA256(preimage) == stored hashlock. Revealing the preimage
'     proves knowledge -> enables cross-leg atomicity (Tier Nolan reveal).
'   - Refund after timeout returns the locked asset to the stored funder
'     (independent per-leg refund; worst case is waiting out your own timeout).
'
' Value movement (the payout legs):
'   - Fund locks the maker's DERO into the SC balance.
'   - Claim (preimage reveal) pays the locked value OUT to the stored taker.
'   - Refund (after timeout, funder only) pays the locked value OUT to the
'     stored funder.
'   The SEND_* legs are executed only when the entrypoint returns 0; a
'   nonzero return ("Discarded knowingly") aborts and the value stays in the
'   SC balance.
'
' State keys (per swap id):
'   _maker, _taker, _sellToken, _sellAmount, _buyToken, _buyAmount,
'   _hashlock, _funded (actual amount locked), _state (0 init, 1 funded,
'   2 settled, 3 refunded), _timeout
' ---------------------------------------------------------------------------

Function CreateSwap(id String, maker String, taker String, sellToken String, sellAmount Uint64, buyToken String, buyAmount Uint64, hashlock String, timeout Uint64) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 100
20 IF sellAmount == 0 THEN GOTO 100
30 IF buyAmount == 0 THEN GOTO 100
40 IF timeout == 0 THEN GOTO 100
50 STORE("swap_" + id + "_maker", maker)
55 STORE("swap_" + id + "_taker", taker)
60 STORE("swap_" + id + "_sellToken", sellToken)
70 STORE("swap_" + id + "_sellAmount", sellAmount)
80 STORE("swap_" + id + "_buyToken", buyToken)
90 STORE("swap_" + id + "_buyAmount", buyAmount)
95 STORE("swap_" + id + "_hashlock", hashlock)
96 STORE("swap_" + id + "_state", 0)
97 STORE("swap_" + id + "_timeout", BLOCK_HEIGHT() + timeout)
98 RETURN 0
100 RETURN 1
End Function

' Fund: the maker locks value into the SC. DEROVALUE() is the amount actually
' sent in this tx; we track the REAL amount (_funded), not the nominal
' sellAmount, so over-funding is captured and refunded in full.
Function Fund(id String, funder String) Uint64
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 IF LOAD("swap_" + id + "_state") != 0 THEN GOTO 100
30 IF LOAD("swap_" + id + "_maker") != funder THEN GOTO 100
40 IF DEROVALUE() < LOAD("swap_" + id + "_sellAmount") THEN GOTO 100
50 STORE("swap_" + id + "_funded", DEROVALUE())
60 STORE("swap_" + id + "_state", 1)
70 RETURN 0
100 RETURN 1
End Function

' Claim: reveal the preimage. SHA256(preimage) must equal the stored
' hashlock. On success, deliver the locked value to the stored taker (the
' counterparty who proves knowledge of the secret) and mark settled.
Function Claim(id String, preimage String) Uint64
10 IF LOAD("swap_" + id + "_state") != 1 THEN GOTO 100
20 IF HEX(SHA256(preimage)) != LOAD("swap_" + id + "_hashlock") THEN GOTO 100
30 SEND_DERO_TO_ADDRESS(LOAD("swap_" + id + "_taker"), LOAD("swap_" + id + "_funded"))
40 STORE("swap_" + id + "_state", 2)
50 RETURN 0
100 RETURN 1
End Function

' Refund: after the timeout, the stored funder (and only the funder) can
' recover the locked value. The refund leg pays back to the stored maker
' address (== funder), so even a griefing call can only ever move value to
' the legitimate owner.
Function Refund(id String, funder String) Uint64
10 IF LOAD("swap_" + id + "_state") != 1 THEN GOTO 100
20 IF BLOCK_HEIGHT() <= LOAD("swap_" + id + "_timeout") THEN GOTO 100
30 IF LOAD("swap_" + id + "_maker") != funder THEN GOTO 100
40 SEND_DERO_TO_ADDRESS(LOAD("swap_" + id + "_maker"), LOAD("swap_" + id + "_funded"))
50 STORE("swap_" + id + "_state", 3)
60 RETURN 0
100 RETURN 1
End Function

Function GetState(id String) Uint64
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_state")
100 RETURN 99
End Function

Function GetMaker(id String) String
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_maker")
100 RETURN ""
End Function

Function GetTaker(id String) String
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_taker")
100 RETURN ""
End Function

Function GetFunded(id String) Uint64
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_funded")
100 RETURN 0
End Function
