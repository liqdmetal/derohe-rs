Function Initialize() Uint64
10 RETURN 0
End Function

Function CreateSwap(id String, sellToken String, sellAmount Uint64, buyToken String, buyAmount Uint64, maker String, timeout Uint64) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 100
20 IF sellAmount == 0 THEN GOTO 100
30 IF buyAmount == 0 THEN GOTO 100
40 STORE("swap_" + id + "_maker", maker)
50 STORE("swap_" + id + "_sellToken", sellToken)
60 STORE("swap_" + id + "_sellAmount", sellAmount)
70 STORE("swap_" + id + "_buyToken", buyToken)
80 STORE("swap_" + id + "_buyAmount", buyAmount)
90 STORE("swap_" + id + "_state", 0)
95 STORE("swap_" + id + "_timeout", BLOCK_HEIGHT() + timeout)
96 RETURN 1
100 RETURN 0
End Function

Function AcceptSwap(id String, taker String) Uint64
10 IF LOAD("swap_" + id + "_state") != 0 THEN GOTO 100
20 IF SIGNER() == LOAD("swap_" + id + "_maker") THEN GOTO 100
30 STORE("swap_" + id + "_taker", taker)
40 STORE("swap_" + id + "_state", 1)
50 RETURN 1
100 RETURN 0
End Function

Function CancelSwap(id String) Uint64
10 IF LOAD("swap_" + id + "_state") == 0 THEN GOTO 40
20 IF LOAD("swap_" + id + "_state") == 1 THEN GOTO 60
30 GOTO 100
40 IF SIGNER() == LOAD("swap_" + id + "_maker") THEN GOTO 50
45 GOTO 100
50 STORE("swap_" + id + "_state", 3)
55 RETURN 1
60 IF BLOCK_HEIGHT() > LOAD("swap_" + id + "_timeout") THEN GOTO 70
65 GOTO 100
70 STORE("swap_" + id + "_state", 3)
75 RETURN 1
100 RETURN 0
End Function

Function GetSwap(id String) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 20
15 RETURN 0
20 RETURN 1
End Function
