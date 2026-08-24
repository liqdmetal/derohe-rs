// derohe-rs differential oracle.
//
// Reads JSON Lines requests on stdin, writes JSON Lines responses on stdout.
// Implements the reference behavior by calling into the REAL derohe Go
// cryptography packages (derohe-reference/), so the Rust implementation can
// be differentially tested against ground truth.
//
// Protocol (one JSON object per line):
//   req:  {"id": <int>, "op": "<op>", "in": { ... }}
//   resp: {"id": <int>, "ok": true, "out": { ... }}
//         {"id": <int>, "ok": false, "err": "<message>"}
//
// Hex strings are lowercase, no 0x prefix.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deroproject/derohe/astrobwt"
	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/dvm"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

type Request struct {
	ID int             `json:"id"`
	Op string          `json:"op"`
	In json.RawMessage `json:"in"`
}

type Response struct {
	ID  int             `json:"id"`
	OK  bool            `json:"ok"`
	Out json.RawMessage `json:"out,omitempty"`
	Err string          `json:"err,omitempty"`
}

func fail(id int, err error) {
	b, _ := json.Marshal(Response{ID: id, OK: false, Err: err.Error()})
	fmt.Println(string(b))
}

func ok(id int, out interface{}) {
	b, _ := json.Marshal(out)
	resp, _ := json.Marshal(Response{ID: id, OK: true, Out: b})
	fmt.Println(string(resp))
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) ([]byte, error) { return hex.DecodeString(s) }

func b32(hexstr string) (*big.Int, error) {
	b, err := unhex(hexstr)
	if err != nil {
		return nil, fmt.Errorf("bad hex: %v", err)
	}
	return new(big.Int).SetBytes(b), nil
}

func decPoint(hexstr string) (*bn256.G1, error) {
	b, err := unhex(hexstr)
	if err != nil {
		return nil, err
	}
	p := new(bn256.G1)
	if err := p.DecodeCompressed(b); err != nil {
		return nil, err
	}
	return p, nil
}

func egFromIn(in map[string]json.RawMessage, prefix string) (*crypto.ElGamal, error) {
	ls, err := s(in, prefix+"left")
	if err != nil {
		return nil, err
	}
	rs, err := s(in, prefix+"right")
	if err != nil {
		return nil, err
	}
	l, err := decPoint(ls)
	if err != nil {
		return nil, fmt.Errorf("%sleft: %v", prefix, err)
	}
	r, err := decPoint(rs)
	if err != nil {
		return nil, fmt.Errorf("%sright: %v", prefix, err)
	}
	return crypto.ConstructElGamal(l, r), nil
}

func egOut(e *crypto.ElGamal) map[string]string {
	return map[string]string{"left": hx(e.Left.EncodeCompressed()), "right": hx(e.Right.EncodeCompressed())}
}

// s reads a string value from the raw input map.
func s(in map[string]json.RawMessage, k string) (string, error) {
	raw, ok := in[k]
	if !ok {
		return "", fmt.Errorf("missing key %s", k)
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	return v, nil
}

// str is an alias for s (used inside statementFromIn where `s` is shadowed).
func str(in map[string]json.RawMessage, k string) (string, error) { return s(in, k) }

// unit vector of given length with 1 at position i
func unitVector(length, i int) *crypto.FieldVector {
	v := make([]*big.Int, length)
	for j := range v {
		v[j] = new(big.Int)
	}
	v[i] = new(big.Int).SetUint64(1)
	return crypto.NewFieldVector(v)
}

// parse a JSON array of hex scalars into a FieldVector
func fvFromRaw(raw json.RawMessage) (*crypto.FieldVector, error) {
	var hexes []string
	if err := json.Unmarshal(raw, &hexes); err != nil {
		return nil, err
	}
	v := make([]*big.Int, len(hexes))
	for i, h := range hexes {
		b, err := unhex(h)
		if err != nil {
			return nil, err
		}
		v[i] = new(big.Int).SetBytes(b)
	}
	return crypto.NewFieldVector(v), nil
}

func fvFromIn(in map[string]json.RawMessage, key string) (*crypto.FieldVector, error) {
	raw, ok := in[key]
	if !ok {
		return nil, fmt.Errorf("missing key %s", key)
	}
	return fvFromRaw(raw)
}

func fvToHex(fv *crypto.FieldVector) []string {
	out := make([]string, fv.Length())
	for i := 0; i < fv.Length(); i++ {
		out[i] = hx(fill32(fv.Element(i)))
	}
	return out
}

// pad big.Int to 32 bytes big-endian
func fill32(x *big.Int) []byte {
	b := x.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// parse JSON array of hex compressed points
func hexListFromRaw(raw json.RawMessage) ([]*bn256.G1, error) {
	var hexes []string
	if err := json.Unmarshal(raw, &hexes); err != nil {
		return nil, err
	}
	pts := make([]*bn256.G1, len(hexes))
	for i, h := range hexes {
		p, err := decPoint(h)
		if err != nil {
			return nil, err
		}
		pts[i] = p
	}
	return pts, nil
}

// parse JSON array of hex big.Ints
func bigListFromRaw(raw json.RawMessage) ([]*big.Int, error) {
	var hexes []string
	if err := json.Unmarshal(raw, &hexes); err != nil {
		return nil, err
	}
	out := make([]*big.Int, len(hexes))
	for i, h := range hexes {
		b, err := unhex(h)
		if err != nil {
			return nil, err
		}
		out[i] = new(big.Int).SetBytes(b)
	}
	return out, nil
}

func bigListToHex(v []*big.Int) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = hx(fill32(x))
	}
	return out
}

// build a Statement + Witness from the request input map
func statementFromIn(in map[string]json.RawMessage) (*crypto.Statement, *crypto.Witness, error) {
	pkRaw, ok := in["publickeylist"]
	if !ok {
		return nil, nil, fmt.Errorf("missing publickeylist")
	}
	var pkHexes []string
	if err := json.Unmarshal(pkRaw, &pkHexes); err != nil {
		return nil, nil, err
	}
	pks := make([]*bn256.G1, len(pkHexes))
	for i, h := range pkHexes {
		p, err := decPoint(h)
		if err != nil {
			return nil, nil, err
		}
		pks[i] = p
	}
	s := &crypto.Statement{
		Publickeylist: pks,
		Bytes_per_publickey: 3,
	}
	// C commitments: array of ElGamal {left,right} — here we pass C = publickeys (simplified, like the reference's tests)
	cRaw, okc := in["c"]
	if !okc {
		return nil, nil, fmt.Errorf("missing c")
	}
	var cHexes []string
	if err := json.Unmarshal(cRaw, &cHexes); err != nil {
		return nil, nil, err
	}
	s.C = make([]*bn256.G1, len(cHexes))
	for i, h := range cHexes {
		p, err := decPoint(h)
		if err != nil {
			return nil, nil, err
		}
		s.C[i] = p
	}
	dHex, err := str(in, "d")
	if err != nil {
		return nil, nil, err
	}
	d, err := decPoint(dHex)
	if err != nil {
		return nil, nil, err
	}
	s.D = d
	// ring pairs: CLn = C, CRn = D (the GenerateProof ring ElGamal basis)
	s.CLn = make([]*bn256.G1, len(s.C))
	s.CRn = make([]*bn256.G1, len(s.C))
	for i := range s.C {
		s.CLn[i] = s.C[i]
		s.CRn[i] = s.D
	}
	// roothash
	rhHex, err := str(in, "roothash")
	if err != nil {
		return nil, nil, err
	}
	rh, err := unhex(rhHex)
	if err != nil {
		return nil, nil, err
	}
	copy(s.Roothash[:], rh[:32])
	// fees
	feesS, err := str(in, "fees")
	if err != nil {
		return nil, nil, err
	}
	var fees uint64
	if _, err := fmt.Sscanf(feesS, "%d", &fees); err != nil {
		return nil, nil, err
	}
	s.Fees = fees
	// witness (optional: verify requests carry only the statement)
	skHex, err := str(in, "secretkey")
	var sk *big.Int
	if err == nil {
		sk, err = b32(skHex)
		if err != nil {
			return nil, nil, err
		}
	} else {
		sk = new(big.Int)
	}
	rHex, err := str(in, "r")
	var rBig *big.Int
	if err == nil {
		rBig, err = b32(rHex)
		if err != nil {
			return nil, nil, err
		}
	} else {
		rBig = new(big.Int)
	}
	trS, err := str(in, "transfer")
	var transfer uint64
	if err == nil {
		if _, err := fmt.Sscanf(trS, "%d", &transfer); err != nil {
			return nil, nil, err
		}
	}
	balS, err := str(in, "balance")
	var balance uint64
	if err == nil {
		if _, err := fmt.Sscanf(balS, "%d", &balance); err != nil {
			return nil, nil, err
		}
	}
	idxRaw, ok := in["index"]
	var idx []int
	if ok {
		if err := json.Unmarshal(idxRaw, &idx); err != nil {
			return nil, nil, err
		}
	} else {
		idx = []int{0, 0}
	}
	w := &crypto.Witness{SecretKey: sk, R: rBig, TransferAmount: transfer, Balance: balance, Index: idx}
	return s, w, nil
}

// rebuild a realistic statement: C[i] = r*pk_i + delta_i*G, D = r*G,
// zero encrypted balances (CLn = C, CRn = D) — mirrors transaction_build.go
func realisticStatement(s *crypto.Statement, w *crypto.Witness, burn uint64) {
	n := len(s.Publickeylist)
	var C []*bn256.G1
	for i := range s.Publickeylist {
		var x bn256.G1
		switch {
		case i == w.Index[0]:
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(0-int64(w.TransferAmount)-int64(s.Fees)-int64(burn)))
		case i == w.Index[1]:
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(int64(w.TransferAmount)))
		default:
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(0))
		}
		x.Add(new(bn256.G1).Set(&x), new(bn256.G1).ScalarMult(s.Publickeylist[i], w.R))
		C = append(C, &x)
	}
	D := new(bn256.G1).ScalarMult(crypto.G, w.R)
	s.C = C
	s.D = D
	s.CLn = make([]*bn256.G1, n)
	s.CRn = make([]*bn256.G1, n)
	for i := 0; i < n; i++ {
		s.CLn[i] = s.C[i]
		s.CRn[i] = s.D
	}
}

// build a Transaction from JSON parts (mirrors txFromIn in the Rust oracle)
func txFromIn(in map[string]json.RawMessage) (*transaction.Transaction, error) {
	tx := &transaction.Transaction{}
	uvar := func(k string) (uint64, error) {
		s, err := str(in, k)
		if err != nil {
			return 0, err
		}
		var v uint64
		if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
			return 0, err
		}
		return v, nil
	}
	hexBytes := func(k string, n int) ([]byte, error) {
		s, err := str(in, k)
		if err != nil {
			return nil, err
		}
		b, err := unhex(s)
		if err != nil {
			return nil, err
		}
		if len(b) != n {
			return nil, fmt.Errorf("%s: expected %d bytes, got %d", k, n, len(b))
		}
		return b, nil
	}

	var err error
	if tx.Version, err = uvar("version"); err != nil {
		return nil, err
	}
	if tx.SourceNetwork, err = uvar("source_network"); err != nil {
		return nil, err
	}
	if tx.DestNetwork, err = uvar("dest_network"); err != nil {
		return nil, err
	}
	tt, err := uvar("txtype")
	if err != nil {
		return nil, err
	}
	tx.TransactionType = transaction.TransactionType(tt)

	if tt == uint64(transaction.PREMINE) || tt == uint64(transaction.SC_TX) {
		if tx.Value, err = uvar("value"); err != nil {
			return nil, err
		}
	}
	if tt == uint64(transaction.PREMINE) || tt == uint64(transaction.COINBASE) || tt == uint64(transaction.REGISTRATION) {
		b, err := hexBytes("miner_address", 33)
		if err != nil {
			return nil, err
		}
		copy(tx.MinerAddress[:], b)
	}
	if tt == uint64(transaction.REGISTRATION) {
		b, err := hexBytes("c", 32)
		if err != nil {
			return nil, err
		}
		copy(tx.C[:], b)
		b, err = hexBytes("s", 32)
		if err != nil {
			return nil, err
		}
		copy(tx.S[:], b)
	}

	if tt == uint64(transaction.BURN_TX) || tt == uint64(transaction.NORMAL) || tt == uint64(transaction.SC_TX) {
		if tx.Height, err = uvar("height"); err != nil {
			return nil, err
		}
		b, err := hexBytes("blid", 32)
		if err != nil {
			return nil, err
		}
		copy(tx.BLID[:], b)

		payRaw, ok := in["payloads"]
		if !ok {
			return nil, fmt.Errorf("missing payloads")
		}
		var payList []json.RawMessage
		if err := json.Unmarshal(payRaw, &payList); err != nil {
			return nil, err
		}
		for _, pj := range payList {
			var pin map[string]json.RawMessage
			if err := json.Unmarshal(pj, &pin); err != nil {
				return nil, err
			}
			var ap transaction.AssetPayload
			burnS, err := str(pin, "burn")
			if err != nil {
				return nil, err
			}
			if _, err := fmt.Sscanf(burnS, "%d", &ap.BurnValue); err != nil {
				return nil, err
			}
			scidB, err := str(pin, "scid")
			if err != nil {
				return nil, err
			}
			scidBytes, err := unhex(scidB)
			if err != nil || len(scidBytes) != 32 {
				return nil, fmt.Errorf("payload scid")
			}
			copy(ap.SCID[:], scidBytes)
			rpctS, err := str(pin, "rpctype")
			if err != nil {
				return nil, err
			}
			var rpct uint64
			fmt.Sscanf(rpctS, "%d", &rpct)
			ap.RPCType = byte(rpct)
			rpcpayS, err := str(pin, "rpcpayload")
			if err != nil {
				return nil, err
			}
			rpcpayB, err := unhex(rpcpayS)
			if err != nil {
				return nil, err
			}
			if len(rpcpayB) != transaction.PAYLOAD_LIMIT {
				return nil, fmt.Errorf("rpcpayload: expected %d bytes, got %d", transaction.PAYLOAD_LIMIT, len(rpcpayB))
			}
			ap.RPCPayload = rpcpayB

			// statement: reuse statementFromIn + realisticStatement
			stmtIn, ok := pin["statement"]
			if !ok {
				return nil, fmt.Errorf("payload statement missing")
			}
			var sim map[string]json.RawMessage
			if err := json.Unmarshal(stmtIn, &sim); err != nil {
				return nil, err
			}
			s, w, err := statementFromIn(sim)
			if err != nil {
				return nil, err
			}
			realisticStatement(s, w, ap.BurnValue)
			ap.Statement = *s

			// proof: serialized bytes -> Proof
			proofS, err := str(pin, "proof")
			if err != nil {
				return nil, err
			}
			proofB, err := unhex(proofS)
			if err != nil {
				return nil, err
			}
			ring := len(ap.Statement.Publickeylist)
			proof, err := crypto.OracleProofDeserialize(proofB, ring/2)
			if err != nil {
				return nil, err
			}
			ap.Proof = proof
			tx.Payloads = append(tx.Payloads, ap)
		}
	}

	if tt == uint64(transaction.SC_TX) {
		scRaw, ok := in["scdata"]
		if !ok {
			return nil, fmt.Errorf("missing scdata")
		}
		var argList []map[string]string
		if err := json.Unmarshal(scRaw, &argList); err != nil {
			return nil, err
		}
		for _, a := range argList {
			arg := rpc.Argument{Name: a["name"], DataType: rpc.DataType(a["datatype"])}
			v := a["value"]
			switch arg.DataType {
			case rpc.DataString:
				arg.Value = v
			case rpc.DataInt64:
				var x int64
				fmt.Sscanf(v, "%d", &x)
				arg.Value = x
			case rpc.DataUint64:
				var x uint64
				fmt.Sscanf(v, "%d", &x)
				arg.Value = x
			case rpc.DataFloat64:
				var x float64
				fmt.Sscanf(v, "%f", &x)
				arg.Value = x
			case rpc.DataHash:
				b, err := unhex(v)
				if err != nil || len(b) != 32 {
					return nil, fmt.Errorf("scdata hash")
				}
				var h crypto.Hash
				copy(h[:], b)
				arg.Value = h
			case rpc.DataAddress:
				b, err := unhex(v)
				if err != nil || len(b) != 33 {
					return nil, fmt.Errorf("scdata address")
				}
				p := new(crypto.Point)
				if err := p.DecodeCompressed(b); err != nil {
					return nil, err
				}
				arg.Value = rpc.Address{PublicKey: p}
			case rpc.DataTime:
				t, err := time.Parse(time.RFC3339Nano, v)
				if err != nil {
					return nil, err
				}
				arg.Value = t
			default:
				return nil, fmt.Errorf("unknown scdata datatype %s", arg.DataType)
			}
			tx.SCDATA = append(tx.SCDATA, arg)
		}
	}
	return tx, nil
}

// ---- Phase 7: block serialization ----------------------------------------

func miniBlockFromIn(in map[string]json.RawMessage) (*block.MiniBlock, error) {
	m := &block.MiniBlock{}
	u8 := func(k string) (uint8, error) {
		s, err := str(in, k)
		if err != nil {
			return 0, err
		}
		var v uint64
		fmt.Sscanf(s, "%d", &v)
		return uint8(v), nil
	}
	u64 := func(k string) (uint64, error) {
		s, err := str(in, k)
		if err != nil {
			return 0, err
		}
		var v uint64
		fmt.Sscanf(s, "%d", &v)
		return v, nil
	}
	var err error
	if m.Version, err = u8("version"); err != nil {
		return nil, err
	}
	m.HighDiff = false
	m.Final = false
	if hd, ok := in["highdiff"]; ok {
		m.HighDiff = string(hd) == "true"
	}
	if f, ok := in["final"]; ok {
		m.Final = string(f) == "true"
	}
	if m.PastCount, err = u8("pastcount"); err != nil {
		return nil, err
	}
	if m.Timestamp, err = func() (uint16, error) {
		v, e := u64("timestamp")
		return uint16(v), e
	}(); err != nil {
		return nil, err
	}
	if m.Height, err = u64("height"); err != nil {
		return nil, err
	}
	pastRaw, ok := in["past"]
	if !ok {
		return nil, fmt.Errorf("missing past")
	}
	var pastHex []string
	if err := json.Unmarshal(pastRaw, &pastHex); err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ {
		if i < len(pastHex) {
			var v uint64
			fmt.Sscanf(pastHex[i], "%d", &v)
			m.Past[i] = uint32(v)
		}
	}
	khS, err := str(in, "keyhash")
	if err != nil {
		return nil, err
	}
	khB, err := unhex(khS)
	if err != nil || len(khB) != 32 {
		return nil, fmt.Errorf("keyhash must be 32 bytes")
	}
	copy(m.KeyHash[:], khB)
	if m.Flags, err = func() (uint32, error) {
		v, e := u64("flags")
		return uint32(v), e
	}(); err != nil {
		return nil, err
	}
	nonceRaw, ok := in["nonce"]
	if !ok {
		return nil, fmt.Errorf("missing nonce")
	}
	var nonceHex []string
	if err := json.Unmarshal(nonceRaw, &nonceHex); err != nil {
		return nil, err
	}
	for i := 0; i < 3; i++ {
		if i < len(nonceHex) {
			var v uint64
			fmt.Sscanf(nonceHex[i], "%d", &v)
			m.Nonce[i] = uint32(v)
		}
	}
	return m, nil
}

func blockFromIn(in map[string]json.RawMessage) (*block.Block, error) {
	bl := &block.Block{}
	u64 := func(k string) (uint64, error) {
		s, err := str(in, k)
		if err != nil {
			return 0, err
		}
		var v uint64
		fmt.Sscanf(s, "%d", &v)
		return v, nil
	}
	var err error
	if bl.Major_Version, err = u64("major"); err != nil {
		return nil, err
	}
	if bl.Minor_Version, err = u64("minor"); err != nil {
		return nil, err
	}
	if bl.Timestamp, err = u64("timestamp"); err != nil {
		return nil, err
	}
	if bl.Height, err = u64("height"); err != nil {
		return nil, err
	}
	txRaw, ok := in["miner_tx"]
	if !ok {
		return nil, fmt.Errorf("missing miner_tx")
	}
	var txIn map[string]json.RawMessage
	if err := json.Unmarshal(txRaw, &txIn); err != nil {
		return nil, err
	}
	tx, err := txFromIn(txIn)
	if err != nil {
		return nil, err
	}
	bl.Miner_TX = *tx

	proofS, err := str(in, "proof")
	if err != nil {
		return nil, err
	}
	proofB, err := unhex(proofS)
	if err != nil || len(proofB) != 32 {
		return nil, fmt.Errorf("proof must be 32 bytes")
	}
	copy(bl.Proof[:], proofB)

	tipsRaw, ok := in["tips"]
	if ok {
		var tipsHex []string
		if err := json.Unmarshal(tipsRaw, &tipsHex); err != nil {
			return nil, err
		}
		for _, h := range tipsHex {
			b, err := unhex(h)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("tip must be 32 bytes")
			}
			var hh crypto.Hash
			copy(hh[:], b)
			bl.Tips = append(bl.Tips, hh)
		}
	}
	mblRaw, ok := in["miniblocks"]
	if ok {
		var mblList []json.RawMessage
		if err := json.Unmarshal(mblRaw, &mblList); err != nil {
			return nil, err
		}
		for _, mj := range mblList {
			var min map[string]json.RawMessage
			if err := json.Unmarshal(mj, &min); err != nil {
				return nil, err
			}
			m, err := miniBlockFromIn(min)
			if err != nil {
				return nil, err
			}
			bl.MiniBlocks = append(bl.MiniBlocks, *m)
		}
	}
	txHRaw, ok := in["tx_hashes"]
	if ok {
		var txHHex []string
		if err := json.Unmarshal(txHRaw, &txHHex); err != nil {
			return nil, err
		}
		for _, h := range txHHex {
			b, err := unhex(h)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("tx_hash must be 32 bytes")
			}
			var hh crypto.Hash
			copy(hh[:], b)
			bl.Tx_hashes = append(bl.Tx_hashes, hh)
		}
	}
	return bl, nil
}

// build a VALID statement + tx exactly like walletapi/transaction_build.go:
//   C[i]  = delta_i*G + r*pk_i           (delta: -v-fees-burn, +v, 0)
//   D     = r*G
//   ebalance[i] = Enc(pk_i, balance_i) = (balance_i*G + eblind_i*pk_i, eblind_i*G)
//   CLn[i] = ebalance[i].Left + C[i]
//   CRn[i] = ebalance[i].Right + D
// with sender balance = value + fees + burn, so the verify algebra cancels.
// Deterministic: RANDOM_OVERRIDE supplies the proof randomness.
func buildValidTx(in map[string]json.RawMessage, ring []*bn256.G1, sk *big.Int, r *big.Int, value, fees, burn uint64, balance []*big.Int, eblind []*big.Int, randHex string) (*transaction.Transaction, error) {
	randBytes, err := unhex(randHex)
	if err != nil {
		return nil, err
	}
	crypto.OracleSetRandomOverride(randBytes)
	defer crypto.OracleSetRandomOverride(nil)

	n := len(ring)
	C := make([]*bn256.G1, n)
	ebalance := make([]*crypto.ElGamal, n)
	CLn := make([]*bn256.G1, n)
	CRn := make([]*bn256.G1, n)
	for i := 0; i < n; i++ {
		var delta *big.Int
		if i == 0 { // sender
			delta = new(big.Int).Neg(new(big.Int).SetUint64(value + fees + burn))
		} else if i == 1 { // receiver
			delta = new(big.Int).SetUint64(value)
		} else {
			delta = new(big.Int)
		}
		x := new(bn256.G1).ScalarMult(crypto.G, delta)
		x.Add(x, new(bn256.G1).ScalarMult(ring[i], r))
		C[i] = x

		// ebalance: Enc(pk_i, balance_i) with blinder eblind[i]
		l := new(bn256.G1).ScalarMult(crypto.G, balance[i])
		l.Add(l, new(bn256.G1).ScalarMult(ring[i], eblind[i]))
		rr := new(bn256.G1).ScalarMult(crypto.G, eblind[i])
		ebalance[i] = crypto.ConstructElGamal(l, rr)

		CLn[i] = new(bn256.G1).Add(ebalance[i].Left, C[i])
		CRn[i] = new(bn256.G1).Add(ebalance[i].Right, new(bn256.G1).ScalarMult(crypto.G, r))
	}
	D := new(bn256.G1).ScalarMult(crypto.G, r)

	roothashS, err := str(in, "roothash")
	if err != nil {
		return nil, err
	}
	roothashB, err := unhex(roothashS)
	if err != nil || len(roothashB) != 32 {
		return nil, fmt.Errorf("roothash must be 32 bytes")
	}
	var roothash crypto.Hash
	copy(roothash[:], roothashB)

	// statement (Publickeylist full — needed for GenerateProof)
	s := &crypto.Statement{
		CLn: CLn, CRn: CRn, Publickeylist: ring, C: C, D: D,
		Roothash: roothash, Fees: fees, Bytes_per_publickey: 3,
	}
	w := &crypto.Witness{SecretKey: sk, R: r, TransferAmount: value, Balance: value + fees + burn, Index: []int{0, 1}}

	var scid crypto.Hash
	copy(scid[:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	scidS, err := str(in, "scid")
	if err == nil {
		scidB, _ := unhex(scidS)
		if len(scidB) == 32 {
			copy(scid[:], scidB)
		}
	}
	// u = upoint * sender_secret (walletapi/transaction_build.go:266) — NOT a
	// random point. The verifier's A_u = upoint*s_sk + u*c_neg only cancels
	// with the prover's committed A_u = upoint*k_sk when u = upoint*sk.
	scid_index := 0
	uinput := append([]byte(crypto.PROTOCOL_CONSTANT), roothash[:]...)
	uinput = append(uinput, scid[:]...)
	uinput = append(uinput, []byte(strconv.Itoa(scid_index))...)
	upoint := crypto.HashToPoint(crypto.HashtoNumber(uinput))
	u := new(bn256.G1).ScalarMult(upoint, sk)

	// witness.Balance = REMAINING balance after the transfer
	// (transaction_build.go:236: balance - value - fees - burn)
	remaining := balance[0].Uint64() - value - fees - burn
	w = &crypto.Witness{SecretKey: sk, R: r, TransferAmount: value, Balance: remaining, Index: []int{0, 1}}
	ap := transaction.AssetPayload{
		SCID: scid, BurnValue: burn, RPCType: 0,
		RPCPayload: make([]byte, transaction.PAYLOAD_LIMIT),
		Statement:  *s,
	}
	tx := &transaction.Transaction{}
	tx.Version = 1
	tx.TransactionType = transaction.NORMAL
	tx.Height = 0
	tx.Payloads = []transaction.AssetPayload{ap}
	txid := tx.GetHash()

	proof := crypto.OracleGenerateProof(scid, 0, s, w, u, txid, burn)
	tx.Payloads[0].Proof = proof
	return tx, nil
}

func optionalStr(in map[string]json.RawMessage, k, dflt string) string {
	if v, ok := in[k]; ok {
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s
		}
	}
	return dflt
}

func must(in map[string]json.RawMessage, k string) string {
	var s string
	json.Unmarshal(in[k], &s)
	return s
}

// parseUint: condensed uint64-field parse (error-checked once per field).
func parseUint(in map[string]json.RawMessage, k string) (uint64, error) {
	return strconv.ParseUint(must(in, k), 10, 64)
}

// strictBool: boolean field that rejects anything but "true"/"false"
// (silently coercing garbage to false is an error-check gap).
func strictBool(in map[string]json.RawMessage, k string) (bool, error) {
	switch optionalStr(in, k, "") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true/false", k)
	}
}

func handle(id int, op string, raw json.RawMessage) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		fail(id, fmt.Errorf("bad input: %v", err))
		return
	}

	switch op {
	case "keccak256", "keccak512":
		data, err := s(in, "data")
		if err != nil {
			fail(id, err)
			return
		}
		db, err := unhex(data)
		if err != nil {
			fail(id, err)
			return
		}
		if op == "keccak256" {
			h := crypto.Keccak256(db)
			ok(id, map[string]string{"hash": hx(h[:])})
		} else {
			h := crypto.Keccak512(db)
			ok(id, map[string]string{"hash": hx(h[:])})
		}

	case "base_g":
		ok(id, map[string]string{"point": hx(crypto.ElGamal_BASE_G.EncodeCompressed())})

	case "pedersen_gparams":
		// global_pedersen_values: G, H, GSUM + hashes pinning all 128 Gs/Hs
		p := crypto.NewPedersenVectorCommitment()
		gh := crypto.Keccak256([]byte{})
		hh := crypto.Keccak256([]byte{})
		// hash of concatenated compressed Gs (128), then Hs
		for i := 0; i < 128; i++ {
			gi := p.Gs.MultiExponentiate(unitVector(128, i))
			hi := p.Hs.MultiExponentiate(unitVector(128, i))
			gh = crypto.Keccak256(gh[:], gi.EncodeCompressed())
			hh = crypto.Keccak256(hh[:], hi.EncodeCompressed())
		}
		g0 := p.Gs.MultiExponentiate(unitVector(128, 0))
		g1 := p.Gs.MultiExponentiate(unitVector(128, 1))
		h0 := p.Hs.MultiExponentiate(unitVector(128, 0))
		h1 := p.Hs.MultiExponentiate(unitVector(128, 1))
		ok(id, map[string]string{
			"g":       hx(p.G.EncodeCompressed()),
			"h":       hx(p.H.EncodeCompressed()),
			"gsum":    hx(p.GSUM.EncodeCompressed()),
			"gs_hash": hx(gh[:]),
			"hs_hash": hx(hh[:]),
			"gs0":     hx(g0.EncodeCompressed()),
			"gs1":     hx(g1.EncodeCompressed()),
			"hs0":     hx(h0.EncodeCompressed()),
			"hs1":     hx(h1.EncodeCompressed()),
		})

	case "pedersen_commit_scalar":
		// G^value * H^randomness (scalar Pedersen)
		p := crypto.NewPedersenCommitmentNew()
		vs, err := s(in, "value")
		if err != nil {
			fail(id, err)
			return
		}
		rs, err := s(in, "randomness")
		if err != nil {
			fail(id, err)
			return
		}
		value, err := b32(vs)
		if err != nil {
			fail(id, err)
			return
		}
		r, err := b32(rs)
		if err != nil {
			fail(id, err)
			return
		}
		point := new(bn256.G1).Add(new(bn256.G1).ScalarMult(p.G, value), new(bn256.G1).ScalarMult(p.H, r))
		ok(id, map[string]string{"point": hx(point.EncodeCompressed())})

	case "pedersen_commit":
		// H^r + Σ Gs[i]^g[i] + Σ Hs[i]^h[i], injected randomness (deterministic)
		gv, err := fvFromIn(in, "gvalues")
		if err != nil {
			fail(id, err)
			return
		}
		hv, err := fvFromIn(in, "hvalues")
		if err != nil {
			fail(id, err)
			return
		}
		rs, err := s(in, "randomness")
		if err != nil {
			fail(id, err)
			return
		}
		r, err := b32(rs)
		if err != nil {
			fail(id, err)
			return
		}
		p := crypto.NewPedersenVectorCommitment()
		point := new(bn256.G1).ScalarMult(p.H, r)
		point = new(bn256.G1).Add(point, p.Gs.MultiExponentiate(gv))
		point = new(bn256.G1).Add(point, p.Hs.MultiExponentiate(hv))
		ok(id, map[string]string{"point": hx(point.EncodeCompressed())})

	case "fieldvector_add":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := fvFromIn(in, "b")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"c": fvToHex(a.Add(b))})

	case "fieldvector_hadamard":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := fvFromIn(in, "b")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"c": fvToHex(a.Hadamard(b))})

	case "fieldvector_innerproduct":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := fvFromIn(in, "b")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]string{"scalar": hx(fill32(a.InnerProduct(b)))})

	case "fieldvector_times":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		ms, err := s(in, "scalar")
		if err != nil {
			fail(id, err)
			return
		}
		m, err := b32(ms)
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"c": fvToHex(a.Times(m))})

	case "fieldvector_negate":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"c": fvToHex(a.Negate())})

	case "fieldvector_flip":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"c": fvToHex(a.Flip())})

	case "fieldvector_extract":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		ps, err := s(in, "parity")
		if err != nil {
			fail(id, err)
			return
		}
		parity := ps == "1"
		ok(id, map[string]interface{}{"c": fvToHex(a.Extract(parity))})

	case "fieldvector_concat":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := fvFromIn(in, "b")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"c": fvToHex(a.Concat(b))})

	case "fieldvector_sum":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]string{"scalar": hx(fill32(a.Sum()))})

	case "pointvector_multexp":
		rawPts, okp := in["points"]
		if !okp {
			fail(id, fmt.Errorf("missing key points"))
			return
		}
		pts, err := hexListFromRaw(rawPts)
		if err != nil {
			fail(id, err)
			return
		}
		exps, err := fvFromIn(in, "exps")
		if err != nil {
			fail(id, err)
			return
		}
		pv := crypto.NewPointVector(pts)
		ok(id, map[string]string{"point": hx(pv.MultiExponentiate(exps).EncodeCompressed())})

	case "hashtopoint":
		seed, err := s(in, "seed")
		if err != nil {
			fail(id, err)
			return
		}
		seedBig, err := b32(seed)
		if err != nil {
			fail(id, err)
			return
		}
		p := crypto.HashToPoint(seedBig)
		ok(id, map[string]string{"point": hx(p.EncodeCompressed())})

	case "point_marshal_uncompressed":
		ps, err := s(in, "point")
		if err != nil {
			fail(id, err)
			return
		}
		p, err := decPoint(ps)
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]string{"point": hx(p.Marshal())})

	case "point_scalarmult":
		ps, err := s(in, "point")
		if err != nil {
			fail(id, err)
			return
		}
		p, err := decPoint(ps)
		if err != nil {
			fail(id, err)
			return
		}
		ks, err := s(in, "scalar")
		if err != nil {
			fail(id, err)
			return
		}
		k, err := b32(ks)
		if err != nil {
			fail(id, err)
			return
		}
		r := new(bn256.G1).ScalarMult(p, k)
		ok(id, map[string]string{"point": hx(r.EncodeCompressed())})

	case "strict_point_decode":
		// Mirror of dvm.strictDecodeG1 (I3/v9 wargame fix): canonical
		// compressed encodings must have x < p. Pins the accept/reject
		// boundary between Go and the clean-room Rust port. Verdict-only
		// output (ok bool) — the error text is diagnostic, the verdict is
		// what must match across implementations.
		ps, err := s(in, "point")
		if err != nil {
			fail(id, err)
			return
		}
		pb, err := hex.DecodeString(ps)
		if err != nil || len(pb) != 33 {
			ok(id, map[string]interface{}{"ok": false})
			return
		}
		xi := new(big.Int).SetBytes(pb[0:32])
		if xi.Cmp(bn256.P) >= 0 {
			ok(id, map[string]interface{}{"ok": false})
			return
		}
		var pt bn256.G1
		if derr := pt.DecodeCompressed(pb); derr != nil {
			ok(id, map[string]interface{}{"ok": false})
			return
		}
		ok(id, map[string]interface{}{"ok": true})

	case "point_add":
		as, err := s(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		bs, err := s(in, "b")
		if err != nil {
			fail(id, err)
			return
		}
		a, err := decPoint(as)
		if err != nil {
			fail(id, err)
			return
		}
		b, err := decPoint(bs)
		if err != nil {
			fail(id, err)
			return
		}
		r := new(bn256.G1).Add(a, b)
		ok(id, map[string]string{"point": hx(r.EncodeCompressed())})

	case "point_neg":
		ps, err := s(in, "point")
		if err != nil {
			fail(id, err)
			return
		}
		p, err := decPoint(ps)
		if err != nil {
			fail(id, err)
			return
		}
		r := new(bn256.G1).Neg(p)
		ok(id, map[string]string{"point": hx(r.EncodeCompressed())})

	case "elgamal_commit": // deterministic: randomness injected by harness
		ks, err := s(in, "key")
		if err != nil {
			fail(id, err)
			return
		}
		key, err := decPoint(ks)
		if err != nil {
			fail(id, err)
			return
		}
		vs, err := s(in, "value")
		if err != nil {
			fail(id, err)
			return
		}
		rs, err := s(in, "randomness")
		if err != nil {
			fail(id, err)
			return
		}
		value, err := b32(vs)
		if err != nil {
			fail(id, err)
			return
		}
		r, err := b32(rs)
		if err != nil {
			fail(id, err)
			return
		}
		// Same scheme as crypto.CommitElGamal, with injected randomness:
		//   Left  = value*G + r*key
		//   Right = r*G
		G := crypto.ElGamal_BASE_G
		left := new(bn256.G1).Add(new(bn256.G1).ScalarMult(G, value), new(bn256.G1).ScalarMult(key, r))
		right := new(bn256.G1).ScalarMult(G, r)
		ok(id, egOut(crypto.ConstructElGamal(left, right)))

	case "elgamal_add":
		a, err := egFromIn(in, "a_")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := egFromIn(in, "b_")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, egOut(a.Add(b)))

	case "elgamal_plus":
		e, err := egFromIn(in, "")
		if err != nil {
			fail(id, err)
			return
		}
		vs, err := s(in, "value")
		if err != nil {
			fail(id, err)
			return
		}
		value, err := b32(vs)
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, egOut(e.Plus(value)))

	case "elgamal_mul":
		e, err := egFromIn(in, "")
		if err != nil {
			fail(id, err)
			return
		}
		ss, err := s(in, "scalar")
		if err != nil {
			fail(id, err)
			return
		}
		scalar, err := b32(ss)
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, egOut(e.Mul(scalar)))

	case "elgamal_neg":
		e, err := egFromIn(in, "")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, egOut(e.Neg()))

	case "elgamal_serialize":
		e, err := egFromIn(in, "")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]string{"bytes": hx(e.Serialize())})

	case "elgamal_deserialize":
		bs, err := s(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(bs)
		if err != nil {
			fail(id, err)
			return
		}
		if len(b) != 66 {
			fail(id, fmt.Errorf("expected 66 bytes, got %d", len(b)))
			return
		}
		e := crypto.ElGamal{}
		func() {
			defer func() {
				if r := recover(); r != nil {
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			e = *e.Deserialize(b)
		}()
		if e.Left != nil {
			ok(id, egOut(&e))
		}

	// ---- Phase 3: FFT / polynomials / inner-product argument -------------

	case "fft_fieldvector":
		a, err := fvFromIn(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		invS, err := s(in, "inverse")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"c": fvToHex(crypto.OracleFFTFieldVector(a, invS == "1"))})

	case "fft_generatorvector":
		rawPts, okp := in["points"]
		if !okp {
			fail(id, fmt.Errorf("missing key points"))
			return
		}
		pts, err := hexListFromRaw(rawPts)
		if err != nil {
			fail(id, err)
			return
		}
		invS, err := s(in, "inverse")
		if err != nil {
			fail(id, err)
			return
		}
		pv := crypto.NewPointVector(pts)
		res := crypto.OracleFFTGeneratorVector(pv, invS == "1")
		elems := crypto.OraclePointVectorElements(res)
		out := make([]string, len(elems))
		for i, p := range elems {
			out[i] = hx(p.EncodeCompressed())
		}
		ok(id, map[string]interface{}{"points": out})

	case "convolution":
		exps, err := fvFromIn(in, "exps")
		if err != nil {
			fail(id, err)
			return
		}
		rawPts, okp := in["points"]
		if !okp {
			fail(id, fmt.Errorf("missing key points"))
			return
		}
		pts, err := hexListFromRaw(rawPts)
		if err != nil {
			fail(id, err)
			return
		}
		pv := crypto.NewPointVector(pts)
		res := crypto.OracleConvolution(exps, pv)
		elems := crypto.OraclePointVectorElements(res)
		out := make([]string, len(elems))
		for i, p := range elems {
			out[i] = hx(p.EncodeCompressed())
		}
		ok(id, map[string]interface{}{"points": out})

	case "polynomial_mul":
		aRaw, oka := in["a"]
		bRaw, okb := in["b"]
		if !oka || !okb {
			fail(id, fmt.Errorf("missing a or b"))
			return
		}
		aBig, err := bigListFromRaw(aRaw)
		if err != nil {
			fail(id, err)
			return
		}
		bBig, err := bigListFromRaw(bRaw)
		if err != nil {
			fail(id, err)
			return
		}
		prod := crypto.NewPolynomial(aBig).Mul(crypto.NewPolynomial(bBig))
		ok(id, map[string]interface{}{"c": bigListToHex(crypto.OraclePolyCoefficients(prod))})

	case "recursive_polynomials":
		aRaw, oka := in["a"]
		bRaw, okb := in["b"]
		if !oka || !okb {
			fail(id, fmt.Errorf("missing a or b"))
			return
		}
		aBig, err := bigListFromRaw(aRaw)
		if err != nil {
			fail(id, err)
			return
		}
		bBig, err := bigListFromRaw(bRaw)
		if err != nil {
			fail(id, err)
			return
		}
		list := crypto.RecursivePolynomials(nil, crypto.NewPolynomial(nil), aBig, bBig)
		out := make([][]string, len(list))
		for i, poly := range list {
			out[i] = bigListToHex(poly)
		}
		ok(id, map[string]interface{}{"list": out})

	case "reducedhash":
		dataS, err := s(in, "data")
		if err != nil {
			fail(id, err)
			return
		}
		data, err := unhex(dataS)
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]string{"scalar": hx(fill32(crypto.OracleReducedHash(data)))})

	case "ip_generate":
		as, err := fvFromIn(in, "as")
		if err != nil {
			fail(id, err)
			return
		}
		bs, err := fvFromIn(in, "bs")
		if err != nil {
			fail(id, err)
			return
		}
		if as.Length() != bs.Length() {
			fail(id, fmt.Errorf("as/bs length mismatch"))
			return
		}
		saltS, err := s(in, "salt")
		if err != nil {
			fail(id, err)
			return
		}
		salt, err := b32(saltS)
		if err != nil {
			fail(id, err)
			return
		}
		n := as.Length()
		gp := crypto.NewGeneratorParams(128)
		gsn := gp.Gs.Slice(0, n)
		hsn := gp.Hs.Slice(0, n)
		// honest P = Σ Gs[i]^as[i] + Σ Hs[i]^bs[i] + H^(as·bs)
		P := gsn.MultiExponentiate(as)
		P = new(bn256.G1).Add(P, hsn.MultiExponentiate(bs))
		P = new(bn256.G1).Add(P, new(bn256.G1).ScalarMult(gp.H, as.InnerProduct(bs)))
		ip := crypto.NewInnerProductProof(
			&crypto.IPStatement{PrimeBase: gp, P: P},
			&crypto.IPWitness{L: as, R: bs},
			salt,
		)
		var buf bytes.Buffer
		ip.Serialize(&buf)
		verified := ip.Verify(crypto.OraclePointVectorElements(hsn), gp.H, P, salt, gp)
		aBig, bBig, ls, rs := crypto.OracleIPParts(ip)
		lsHex := make([]string, len(ls))
		rsHex := make([]string, len(rs))
		for i := range ls {
			lsHex[i] = hx(ls[i].EncodeCompressed())
			rsHex[i] = hx(rs[i].EncodeCompressed())
		}
		hsHex := make([]string, n)
		for i := 0; i < n; i++ {
			hsHex[i] = hx(crypto.OraclePointVectorElements(hsn)[i].EncodeCompressed())
		}
		ok(id, map[string]interface{}{
			"proof":    hx(buf.Bytes()),
			"p":        hx(P.EncodeCompressed()),
			"verified": verified,
			"a":        hx(fill32(aBig)),
			"b":        hx(fill32(bBig)),
			"ls":       lsHex,
			"rs":       rsHex,
			"hs":       hsHex,
		})

	case "ip_verify":
		aS, err := s(in, "a")
		if err != nil {
			fail(id, err)
			return
		}
		bS, err := s(in, "b")
		if err != nil {
			fail(id, err)
			return
		}
		aBig, err := b32(aS)
		if err != nil {
			fail(id, err)
			return
		}
		bBig, err := b32(bS)
		if err != nil {
			fail(id, err)
			return
		}
		saltS, err := s(in, "salt")
		if err != nil {
			fail(id, err)
			return
		}
		salt, err := b32(saltS)
		if err != nil {
			fail(id, err)
			return
		}
		pS, err := s(in, "p")
		if err != nil {
			fail(id, err)
			return
		}
		P, err := decPoint(pS)
		if err != nil {
			fail(id, err)
			return
		}
		lsRaw, okl := in["ls"]
		rsRaw, okr := in["rs"]
		hsRaw, okh := in["hs"]
		if !okl || !okr || !okh {
			fail(id, fmt.Errorf("missing ls/rs/hs"))
			return
		}
		ls, err := hexListFromRaw(lsRaw)
		if err != nil {
			fail(id, err)
			return
		}
		rs, err := hexListFromRaw(rsRaw)
		if err != nil {
			fail(id, err)
			return
		}
		hs, err := hexListFromRaw(hsRaw)
		if err != nil {
			fail(id, err)
			return
		}
		ip := crypto.OracleNewInnerProduct(aBig, bBig, ls, rs)
		gp := crypto.NewGeneratorParams(128)
		ok(id, map[string]interface{}{"verified": ip.Verify(hs, gp.H, P, salt, gp)})

	// ---- Phase 4: aggregate bulletproof (GenerateProof/Verify) ------------

	case "proof_generate":
		// deterministic randomness: the harness supplies the byte stream
		// consumed by the 11 RandomScalarFixed calls (sL, sR, aa, phi/chi/psi,
		// k_sk/k_r/k_b/k_tau) + CommitElGamal random values (all via
		// RandomScalarFixed).
		randHex, err := str(in, "rand")
		if err != nil {
			fail(id, err)
			return
		}
		randBytes, err := unhex(randHex)
		if err != nil {
			fail(id, err)
			return
		}
		crypto.OracleSetRandomOverride(randBytes)
		defer crypto.OracleSetRandomOverride(nil)

		scidHex, err := str(in, "scid")
		if err != nil {
			fail(id, err)
			return
		}
		scidBytes, err := unhex(scidHex)
		if err != nil {
			fail(id, err)
			return
		}
		var scid crypto.Hash
		copy(scid[:], scidBytes[:32])
		scidIndex, err := str(in, "scid_index")
		if err != nil {
			fail(id, err)
			return
		}
		var scidIdx int
		if _, err := fmt.Sscanf(scidIndex, "%d", &scidIdx); err != nil {
			fail(id, err)
			return
		}
		txidHex, err := str(in, "txid")
		if err != nil {
			fail(id, err)
			return
		}
		txidBytes, err := unhex(txidHex)
		if err != nil {
			fail(id, err)
			return
		}
		var txid crypto.Hash
		copy(txid[:], txidBytes[:32])
		burnS, err := str(in, "burn")
		if err != nil {
			fail(id, err)
			return
		}
		var burn uint64
		if _, err := fmt.Sscanf(burnS, "%d", &burn); err != nil {
			fail(id, err)
			return
		}
		uHex, err := str(in, "u")
		if err != nil {
			fail(id, err)
			return
		}
		u, err := decPoint(uHex)
		if err != nil {
			fail(id, err)
			return
		}
		// generate with the realistic statement (amount-structured C/D)
		sReal, wReal, err := statementFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
		realisticStatement(sReal, wReal, burn)
		proof := crypto.OracleGenerateProof(scid, scidIdx, sReal, wReal, u, txid, burn)
		ser := crypto.OracleProofSerialize(proof)
		nonce := crypto.OracleProofNonce(proof)
		parity := crypto.OracleProofParity(proof)
		// in-process self-verify (no deserialize): isolates equation vs roundtrip
		self_ok, _ := crypto.OracleVerifyProof(crypto.ZEROHASH, scid, scidIdx, sReal, proof, txid, burn)
		ok(id, map[string]interface{}{
			"proof": hx(ser),
			"nonce": hx(nonce[:]),
			"parity": parity,
			"self_verified": self_ok,
		})

	case "bp_debug":
		s, w, err := statementFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
		randHex, err := str(in, "rand")
		if err != nil {
			fail(id, err)
			return
		}
		randBytes, err := unhex(randHex)
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, crypto.OracleBPDebug(s, w, randBytes))

	case "proof_verify_trace":
		s, w, err := statementFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
		// verbatim statement support (like proof_verify)
		burnS2, _ := str(in, "burn")
		var burn2 uint64
		fmt.Sscanf(burnS2, "%d", &burn2)
		if _, hasCln := in["cln"]; hasCln {
			for _, key := range []string{"cln", "crn", "c"} {
				raw, ok := in[key]
				if !ok {
					fail(id, fmt.Errorf("missing %s", key))
					return
				}
				var hexes []string
				if err := json.Unmarshal(raw, &hexes); err != nil {
					fail(id, err)
					return
				}
				var list []*bn256.G1
				for _, h := range hexes {
					p, err := decPoint(h)
					if err != nil {
						fail(id, err)
						return
					}
					list = append(list, p)
				}
				switch key {
				case "cln":
					s.CLn = list
				case "crn":
					s.CRn = list
				case "c":
					s.C = list
				}
			}
			dHex, err := str(in, "d")
			if err != nil {
				fail(id, err)
				return
			}
			s.D, err = decPoint(dHex)
			if err != nil {
				fail(id, err)
				return
			}
		} else {
			realisticStatement(s, w, burn2)
		}
		proofHex, err := str(in, "proof")
		if err != nil {
			fail(id, err)
			return
		}
		proofBytes, err := unhex(proofHex)
		if err != nil {
			fail(id, err)
			return
		}
		length := len(s.Publickeylist) / 2
		proof, err := crypto.OracleProofDeserialize(proofBytes, length)
		if err != nil {
			fail(id, err)
			return
		}
		txidHex, err := str(in, "txid")
		if err != nil {
			fail(id, err)
			return
		}
		txidBytes, err := unhex(txidHex)
		if err != nil {
			fail(id, err)
			return
		}
		var txid crypto.Hash
		copy(txid[:], txidBytes[:32])
		burnS, err := str(in, "burn")
		if err != nil {
			fail(id, err)
			return
		}
		var burn uint64
		if _, err := fmt.Sscanf(burnS, "%d", &burn); err != nil {
			fail(id, err)
			return
		}
		scidHex, err := str(in, "scid")
		if err != nil {
			fail(id, err)
			return
		}
		scidBytes, err := unhex(scidHex)
		if err != nil {
			fail(id, err)
			return
		}
		var scidV crypto.Hash
		copy(scidV[:], scidBytes[:32])
		scidIdxS, err := str(in, "scid_index")
		if err != nil {
			fail(id, err)
			return
		}
		var scidIdxV int
		if _, err := fmt.Sscanf(scidIdxS, "%d", &scidIdxV); err != nil {
			fail(id, err)
			return
		}
		ok(id, crypto.OracleVerifyTrace(s, proof, txid, burn, scidV, scidIdxV))

	case "proof_verify":
		s, w, err := statementFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
		// when the full statement (cln/crn/c/d) is supplied, use it verbatim
		// (valid-tx accept testing) instead of rebuilding from the witness
		_, hasCln := in["cln"]
		if hasCln {
			for _, key := range []string{"cln", "crn", "c"} {
				raw, ok := in[key]
				if !ok {
					fail(id, fmt.Errorf("missing %s", key))
					return
				}
				var hexes []string
				if err := json.Unmarshal(raw, &hexes); err != nil {
					fail(id, err)
					return
				}
				var list []*bn256.G1
				for _, h := range hexes {
					p, err := decPoint(h)
					if err != nil {
						fail(id, err)
						return
					}
					list = append(list, p)
				}
				switch key {
				case "cln":
					s.CLn = list
				case "crn":
					s.CRn = list
				case "c":
					s.C = list
				}
			}
			dHex, err := str(in, "d")
			if err != nil {
				fail(id, err)
				return
			}
			s.D, err = decPoint(dHex)
			if err != nil {
				fail(id, err)
				return
			}
		}
		proofHex, err := str(in, "proof")
		if err != nil {
			fail(id, err)
			return
		}
		proofBytes, err := unhex(proofHex)
		if err != nil {
			fail(id, err)
			return
		}
		length := len(s.Publickeylist) / 2 // CLnG length == N/2 (m)
		proof, err := crypto.OracleProofDeserialize(proofBytes, length)
		if err != nil {
			fail(id, err)
			return
		}
		scidHex, err := str(in, "scid")
		if err != nil {
			fail(id, err)
			return
		}
		scidBytes, err := unhex(scidHex)
		if err != nil {
			fail(id, err)
			return
		}
		var scid crypto.Hash
		copy(scid[:], scidBytes[:32])
		scidIndex, err := str(in, "scid_index")
		if err != nil {
			fail(id, err)
			return
		}
		var scidIdx int
		if _, err := fmt.Sscanf(scidIndex, "%d", &scidIdx); err != nil {
			fail(id, err)
			return
		}
		txidHex, err := str(in, "txid")
		if err != nil {
			fail(id, err)
			return
		}
		txidBytes, err := unhex(txidHex)
		if err != nil {
			fail(id, err)
			return
		}
		var txid crypto.Hash
		copy(txid[:], txidBytes[:32])
		burnS, err := str(in, "burn")
		if err != nil {
			fail(id, err)
			return
		}
		var burn uint64
		if _, err := fmt.Sscanf(burnS, "%d", &burn); err != nil {
			fail(id, err)
			return
		}
		if !hasCln {
			realisticStatement(s, w, burn)
		}
		verified := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Go reference PANICS on corrupted/malformed proofs
					// ("Faulty or invalid proof"). The oracle maps that to a
					// clean REJECT (verified=false), matching the Rust side.
					verified = false
				}
			}()
			verified, _ = crypto.OracleVerifyProof(crypto.ZEROHASH, scid, scidIdx, s, proof, txid, burn)
		}()
		ok(id, map[string]interface{}{"verified": verified})

	// ---- Phase 5: balance serialization (NonceBalance) --------------------

	case "noncebalance_marshal":
		nhS, err := str(in, "nonceheight")
		if err != nil {
			fail(id, err)
			return
		}
		var nh uint64
		if _, err := fmt.Sscanf(nhS, "%d", &nh); err != nil {
			fail(id, err)
			return
		}
		balHex, err := str(in, "balance")
		if err != nil {
			fail(id, err)
			return
		}
		balBytes, err := unhex(balHex)
		if err != nil {
			fail(id, err)
			return
		}
		if len(balBytes) != 66 {
			fail(id, fmt.Errorf("expected 66 bytes, got %d", len(balBytes)))
			return
		}
		var bal crypto.ElGamal
		func() {
			defer func() {
				if r := recover(); r != nil {
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			bal = *new(crypto.ElGamal).Deserialize(balBytes)
		}()
		if bal.Left == nil {
			return
		}
		nb := &crypto.NonceBalance{NonceHeight: nh, Balance: &bal}
		ok(id, map[string]interface{}{"bytes": hx(nb.Marshal())})

	case "noncebalance_unmarshal":
		hexS, err := str(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(hexS)
		if err != nil {
			fail(id, err)
			return
		}
		var nb crypto.NonceBalance
		func() {
			defer func() {
				if r := recover(); r != nil {
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			nb = *new(crypto.NonceBalance).Unmarshal(b)
		}()
		if nb.Balance == nil {
			return
		}
		ok(id, map[string]interface{}{
			"nonceheight": nb.NonceHeight,
			"balance":     hx(nb.Balance.Serialize()),
		})

	case "noncebalance_unmarshal_nonce":
		hexS, err := str(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(hexS)
		if err != nil {
			fail(id, err)
			return
		}
		var nb crypto.NonceBalance
		func() {
			defer func() {
				if r := recover(); r != nil {
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			nb.UnmarshalNonce(b)
		}()
		ok(id, map[string]interface{}{"nonceheight": nb.NonceHeight})

	// ---- Phase 6: transaction serialization -------------------------------

	case "tx_serialize":
		tx, err := txFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
		var ser, header, core, hash []byte
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			ser = tx.Serialize()
			header = tx.SerializeHeader()
			core = tx.SerializeCoreStatement()
			h := tx.GetHash()
			hash = h[:]
		}()
		if panicked {
			return
		}
		ok(id, map[string]interface{}{
			"bytes": hx(ser), "header": hx(header), "core": hx(core), "hash": hx(hash),
		})

	case "tx_deserialize":
		hexS, err := str(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(hexS)
		if err != nil {
			fail(id, err)
			return
		}
		var tx transaction.Transaction
		var derr error
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			derr = tx.Deserialize(b)
		}()
		if panicked {
			return
		}
		if derr != nil {
			fail(id, derr)
			return
		}
		if tx.Version == 0 && len(tx.Payloads) == 0 && tx.TransactionType == 0 {
			return
		}
		var ser []byte
		var h crypto.Hash
		panicked = false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			ser = tx.Serialize()
			h = tx.GetHash()
		}()
		if panicked {
			return
		}
		ok(id, map[string]interface{}{"bytes": hx(ser), "hash": hx(h[:])})

	// ---- Phase 7: block serialization -------------------------------------

	case "block_serialize":
		bl, err := blockFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
		var ser, serSkip, hash, hashSkip, tipsHash, txsHash []byte
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			ser = bl.Serialize()
			serSkip = bl.SerializeWithoutLastMiniBlock()
			h := bl.GetHash()
			hash = h[:]
			h2 := bl.GetHashSkipLastMiniBlock()
			hashSkip = h2[:]
			h3 := bl.GetTipsHash()
			tipsHash = h3[:]
			h4 := bl.GetTXSHash()
			txsHash = h4[:]
		}()
		if panicked {
			return
		}
		ok(id, map[string]interface{}{
			"bytes": hx(ser), "bytes_skip_last": hx(serSkip),
			"hash": hx(hash), "hash_skip_last": hx(hashSkip),
			"tips_hash": hx(tipsHash), "txs_hash": hx(txsHash),
		})

	case "block_deserialize":
		hexS, err := str(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(hexS)
		if err != nil {
			fail(id, err)
			return
		}
		var bl block.Block
		derr := bl.Deserialize(b)
		if derr != nil {
			fail(id, derr)
			return
		}
		var ser, hash, minerHash []byte
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					fail(id, fmt.Errorf("panic: %v", r))
				}
			}()
			ser = bl.Serialize()
			h := bl.GetHash()
			hash = h[:]
			mh := bl.Miner_TX.GetHash()
			minerHash = mh[:]
		}()
		if panicked {
			return
		}
		// mirror the Rust oracle's miner_statements (roothash/fees/ring per
		// miner-tx payload) so the differential compares like-for-like
		minerStmts := []map[string]interface{}{}
		for _, p := range bl.Miner_TX.Payloads {
			st := &p.Statement
			minerStmts = append(minerStmts, map[string]interface{}{
				"roothash": hx(st.Roothash[:]),
				"fees":     fmt.Sprintf("%d", st.Fees),
				"ring":     len(st.Publickeylist_pointers) / int(st.Bytes_per_publickey),
			})
		}
		ok(id, map[string]interface{}{"bytes": hx(ser), "hash": hx(hash), "miner_tx_hash": hx(minerHash), "miner_statements": minerStmts})

	// ---- Phase 8: valid-transaction accept path ---------------------------

	case "tx_build_valid":
		pkRaw, hasPk := in["publickeylist"]
		if !hasPk {
			fail(id, fmt.Errorf("missing publickeylist"))
			return
		}
		var pkHex []string
		if err := json.Unmarshal(pkRaw, &pkHex); err != nil {
			fail(id, err)
			return
		}
		ring := make([]*bn256.G1, len(pkHex))
		for i, h := range pkHex {
			p, err := decPoint(h)
			if err != nil {
				fail(id, err)
				return
			}
			ring[i] = p
		}
		skHex, err := str(in, "secretkey")
		if err != nil {
			fail(id, err)
			return
		}
		sk, err := b32(skHex)
		if err != nil {
			fail(id, err)
			return
		}
		rHex, err := str(in, "r")
		if err != nil {
			fail(id, err)
			return
		}
		rBig, err := b32(rHex)
		if err != nil {
			fail(id, err)
			return
		}
		valS, err := str(in, "value")
		if err != nil {
			fail(id, err)
			return
		}
		var value uint64
		fmt.Sscanf(valS, "%d", &value)
		feesS, err := str(in, "fees")
		if err != nil {
			fail(id, err)
			return
		}
		var fees uint64
		fmt.Sscanf(feesS, "%d", &fees)
		burnS, err := str(in, "burn")
		if err != nil {
			fail(id, err)
			return
		}
		var burn uint64
		fmt.Sscanf(burnS, "%d", &burn)
		balRaw, hasBal := in["balances"]
		if !hasBal {
			fail(id, fmt.Errorf("missing balances"))
			return
		}
		var balHex []string
		if err := json.Unmarshal(balRaw, &balHex); err != nil {
			fail(id, err)
			return
		}
		balance := make([]*big.Int, len(balHex))
		for i, h := range balHex {
			balance[i], _ = new(big.Int).SetString(h, 16)
		}
		ebRaw, hasEb := in["eblind"]
		if !hasEb {
			fail(id, fmt.Errorf("missing eblind"))
			return
		}
		var ebHex []string
		if err := json.Unmarshal(ebRaw, &ebHex); err != nil {
			fail(id, err)
			return
		}
		eblind := make([]*big.Int, len(ebHex))
		for i, h := range ebHex {
			eblind[i], _ = new(big.Int).SetString(h, 16)
		}
		randHex, err := str(in, "rand")
		if err != nil {
			fail(id, err)
			return
		}
		crypto.OracleSigmaSnapshot = &crypto.SigmaSnapshot{}
		tx, err := buildValidTx(in, ring, sk, rBig, value, fees, burn, balance, eblind, randHex)
		snap := crypto.OracleSigmaSnapshot
		crypto.OracleSigmaSnapshot = nil
		if err != nil {
			fail(id, err)
			return
		}
		var ser, hash []byte
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					fail(id, fmt.Errorf("panic: %v\n%s", r, string(debug.Stack())))
				}
			}()
			ser = tx.Serialize()
			h := tx.GetHash()
			hash = h[:]
		}()
		if panicked {
			return
		}
		var txid crypto.Hash
		copy(txid[:], hash)
		selfAccepted, _ := crypto.OracleVerifyProof(crypto.ZEROHASH, tx.Payloads[0].SCID, 0, &tx.Payloads[0].Statement, tx.Payloads[0].Proof, txid, burn)
		clnHex := make([]string, len(tx.Payloads[0].Statement.CLn))
		crnHex := make([]string, len(tx.Payloads[0].Statement.CRn))
		cHex := make([]string, len(tx.Payloads[0].Statement.C))
		for i := range clnHex {
			clnHex[i] = hx(tx.Payloads[0].Statement.CLn[i].EncodeCompressed())
			crnHex[i] = hx(tx.Payloads[0].Statement.CRn[i].EncodeCompressed())
			cHex[i] = hx(tx.Payloads[0].Statement.C[i].EncodeCompressed())
		}
		ok(id, map[string]interface{}{
			"bytes": hx(ser), "hash": hx(hash),
			"proof": hx(crypto.OracleProofSerialize(tx.Payloads[0].Proof)),
			"accepted": selfAccepted,
			"c": cHex, "cln": clnHex, "crn": crnHex,
			"d": hx(tx.Payloads[0].Statement.D.EncodeCompressed()),
			"roothash": hx(tx.Payloads[0].Statement.Roothash[:]),
			"fees": fmt.Sprintf("%d", tx.Payloads[0].Statement.Fees),
			"snap_ay": snap.AY.String(), "snap_ad": snap.AD.String(),
			"snap_ab": snap.AB.String(), "snap_ax": snap.AX.String(),
			"snap_at": snap.AT.String(), "snap_au": snap.AU.String(),
			"snap_cnr_right": snap.CnRRight.String(), "snap_dr": snap.DR.String(),
			"snap_gr": snap.GR.String(), "snap_yxr": snap.YXR.String(),
			"snap_cxr_right": snap.CXRRight.String(),
		})

	// ---- Phase 8: AstroBWT PoW -------------------------------------------

	case "pow32":
		bS, err := str(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(bS)
		if err != nil {
			fail(id, err)
			return
		}
		h := astrobwt.POW32(b)
		ok(id, map[string]interface{}{"hash": hx(h[:])})

	case "pow_v3":
		bS, err := str(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(bS)
		if err != nil {
			fail(id, err)
			return
		}
		h := astrobwtv3.AstroBWTv3(b)
		ok(id, map[string]interface{}{"hash": hx(h[:])})

	case "pow_v3_debug":
		bS, err := str(in, "bytes")
		if err != nil {
			fail(id, err)
			return
		}
		b, err := unhex(bS)
		if err != nil {
			fail(id, err)
			return
		}
		dbg := &astrobwtv3.V3Debug{}
		astrobwtv3.OracleV3Debug = dbg
		h := astrobwtv3.AstroBWTv3(b)
		astrobwtv3.OracleV3Debug = nil
		posLogHex := ""
		for _, v := range dbg.PosLog[:] {
			posLogHex += fmt.Sprintf("%08x", v)
		}
		switchLogHex := ""
		for _, v := range dbg.SwitchLog[:] {
			switchLogHex += fmt.Sprintf("%016x", v)
		}
		ok(id, map[string]interface{}{
			"hash":          hx(h[:]),
			"sha_key":       hx(dbg.ShaKey[:]),
			"after_salsa":   hx(dbg.AfterSalsa[:]),
			"after_rc4":     hx(dbg.AfterRc4[:]),
			"lhash":         fmt.Sprintf("%d", dbg.Lhash),
			"prev_lhash":    fmt.Sprintf("%d", dbg.PrevLhash),
			"iter1_switch":  fmt.Sprintf("%d", dbg.Iter1Switch),
			"iter1_op":      fmt.Sprintf("%d", dbg.Iter1Op),
			"iter1_pos1":    fmt.Sprintf("%d", dbg.Iter1Pos1),
			"iter1_pos2":    fmt.Sprintf("%d", dbg.Iter1Pos2),
			"iter1_state":   hx(dbg.Iter1State[:]),
			"iter1_lhash":   fmt.Sprintf("%d", dbg.Iter1Lhash),
			"iter1_prev":    fmt.Sprintf("%d", dbg.Iter1Prev),
			"iter1_after_a": fmt.Sprintf("%d", dbg.Iter1AfterA),
			"iter1_pa":      fmt.Sprintf("%d", dbg.Iter1PrevAfterA),
			"iter1_after_b": fmt.Sprintf("%d", dbg.Iter1AfterB),
			"iter1_pb":      fmt.Sprintf("%d", dbg.Iter1PrevAfterB),
			"iter1_after_c": fmt.Sprintf("%d", dbg.Iter1AfterC),
			"iter1_pc":      fmt.Sprintf("%d", dbg.Iter1PrevAfterC),
			"tries":         fmt.Sprintf("%d", dbg.Tries),
			"data_len":      fmt.Sprintf("%d", dbg.DataLen),
			"final_state":   hx(dbg.FinalState[:]),
			"data_prefix":   hx(dbg.DataPrefix[:]),
			"data_prefix2":  hx(dbg.DataPrefix2[:]),
			"data_prefix200": hx(dbg.DataPrefix200[:]),
			"data_full":      hx([]byte(dbg.DataFull)),
			"op_log":         fmt.Sprintf("%x", dbg.OpLog[:]),
			"pos_log":        posLogHex,
			"switch_log":     switchLogHex,
		})

	case "check_pow":
		// CheckPowHashBig (blockchain/difficulty.go): valid iff
		// LE-int(hash) <= 2^256/difficulty
		hS, err := str(in, "hash")
		if err != nil {
			fail(id, err)
			return
		}
		hB, err := unhex(hS)
		if err != nil || len(hB) != 32 {
			fail(id, fmt.Errorf("hash must be 32 bytes"))
			return
		}
		dS, err := str(in, "difficulty")
		if err != nil {
			fail(id, err)
			return
		}
		d, okd := new(big.Int).SetString(dS, 10)
		if !okd {
			fail(id, fmt.Errorf("bad difficulty"))
			return
		}
		// HashToBig: reverse to big-endian then SetBytes
		rev := make([]byte, 32)
		for i := 0; i < 16; i++ {
			rev[i], rev[31-i] = hB[31-i], hB[i]
		}
		powHashBig := new(big.Int).SetBytes(rev)
		oneLsh256 := new(big.Int).Lsh(big.NewInt(1), 256)
		target := new(big.Int).Div(oneLsh256, d)
		valid := powHashBig.Cmp(target) <= 0
		ok(id, map[string]interface{}{"valid": valid})

	// ---- Phase 9: DVM ----------------------------------------------------

	case "dvm_parse":
		code, err := str(in, "code")
		if err != nil {
			fail(id, err)
			return
		}
		sc, _, perr := dvm.ParseSmartContract(code)
		if perr != nil {
			ok(id, map[string]interface{}{"ok": false, "err": perr.Error()})
			return
		}
		names := []string{}
		for name := range sc.Functions {
			names = append(names, name)
		}
		sort.Strings(names)
		out := map[string]interface{}{"ok": true, "functions": names}
		for _, name := range names {
			f := sc.Functions[name]
			paramtypes := []string{}
			for _, p := range f.Params {
				paramtypes = append(paramtypes, fmt.Sprintf("%d", p.Type))
			}
			lines := []string{}
			for _, ln := range f.LineNumbers {
				lines = append(lines, fmt.Sprintf("%d:%s", ln, strings.Join(f.Lines[ln], " ")))
			}
			out["fn_"+name] = map[string]interface{}{
				"ret":    fmt.Sprintf("%d", f.ReturnValue.Type),
				"params": paramtypes,
				"lines":  lines,
			}
		}
		ok(id, out)

	case "dvm_uses_signer":
		code, err := str(in, "code")
		if err != nil {
			fail(id, err)
			return
		}
		sc, _, perr := dvm.ParseSmartContract(code)
		if perr != nil {
			ok(id, map[string]interface{}{"ok": false, "err": perr.Error()})
			return
		}
		// K0 Fix B2 mirror: true iff any function line token == SIGNER
		// (case-insensitive, matching the DVM's dispatch).
		uses := false
		for _, fn := range sc.Functions {
			for _, line := range fn.Lines {
				for _, tok := range line {
					if strings.EqualFold(tok, "SIGNER") {
						uses = true
						break
					}
				}
				if uses {
					break
				}
			}
			if uses {
				break
			}
		}
		ok(id, map[string]interface{}{"ok": true, "uses_signer": uses})

	case "dvm_rnd":
		scidS, _ := str(in, "scid")
		blidS, _ := str(in, "blid")
		txidS, _ := str(in, "txid")
		var scid, blid, txid crypto.Hash
		if scidS != "" {
			scidB, _ := unhex(scidS)
			copy(scid[:], scidB)
		}
		if blidS != "" {
			blidB, _ := unhex(blidS)
			copy(blid[:], blidB)
		}
		if txidS != "" {
			txidB, _ := unhex(txidS)
			copy(txid[:], txidB)
		}
		r := dvm.Initialize_RND(scid, blid, txid)
		n, _ := strconv.ParseUint(optionalStr(in, "n", "5"), 10, 64)
		vals := []string{}
		for i := uint64(0); i < n; i++ {
			vals = append(vals, fmt.Sprintf("%d", r.Random()))
		}
		ok(id, map[string]interface{}{"vals": vals})

	case "dvm_run":
		code, err := str(in, "code")
		if err != nil {
			fail(id, err)
			return
		}
		sc, _, perr := dvm.ParseSmartContract(code)
		if perr != nil {
			fail(id, perr)
			return
		}
		var scid, blid, txid crypto.Hash
		scidS, _ := str(in, "scid")
		if scidS != "" {
			scidB, _ := unhex(scidS)
			copy(scid[:], scidB)
		}
		blidS, _ := str(in, "blid")
		if blidS != "" {
			blidB, _ := unhex(blidS)
			copy(blid[:], blidB)
		}
		txidS, _ := str(in, "txid")
		if txidS != "" {
			txidB, _ := unhex(txidS)
			copy(txid[:], txidB)
		}
		entrypoint, _ := str(in, "entrypoint")
		params := map[string]interface{}{}
		if pr, ok := in["params"]; ok {
			var pm map[string]interface{}
			json.Unmarshal(pr, &pm)
			for k, v := range pm {
				params[k] = v
			}
		}
		height, _ := strconv.ParseUint(optionalStr(in, "height", "0"), 10, 64)
		ts, _ := strconv.ParseUint(optionalStr(in, "timestamp", "0"), 10, 64)
		state := &dvm.Shared_State{
			SCIDZERO:        [32]byte{},
			SCIDSELF:        scid,
			GasComputeLimit: 10000000,
			GasComputeCheck: true,
			Chain_inputs: &dvm.Blockchain_Input{
				SCID: scid, BLID: blid, TXID: txid, BL_HEIGHT: height, BL_TIMESTAMP: ts,
				Signer: optionalStr(in, "signer", ""),
			},
			Assets:          map[crypto.Hash]uint64{},
			RamStore:        map[dvm.Variable]dvm.Variable{},
			RND:             dvm.Initialize_RND(scid, blid, txid),
			Store:           dvm.Initialize_TX_store(),
			Assets_Transfer: map[string]map[string]uint64{},
		}
		state.Store.State = state
		result, rerr := dvm.RunSmartContract(&sc, entrypoint, state, params)
		if rerr != nil {
			ok(id, map[string]interface{}{
				"ok":          false,
				"err":         rerr.Error(),
				"gas_compute": fmt.Sprintf("%d", state.GasComputeUsed),
				"gas_storage": fmt.Sprintf("%d", state.GasStoreUsed),
				"ops":         fmt.Sprintf("%d", state.Monitor_ops),
				"lines":       fmt.Sprintf("%d", state.Monitor_lines_interpreted),
			})
			return
		}
		out := map[string]interface{}{
			"ok":          true,
			"ret_type":    fmt.Sprintf("%d", result.Type),
			"gas_compute": fmt.Sprintf("%d", state.GasComputeUsed),
			"gas_storage": fmt.Sprintf("%d", state.GasStoreUsed),
			"ops":         fmt.Sprintf("%d", state.Monitor_ops),
			"lines":       fmt.Sprintf("%d", state.Monitor_lines_interpreted),
		}
		if result.Type == dvm.Uint64 {
			out["ret"] = fmt.Sprintf("%d", result.ValueUint64)
		} else if result.Type == dvm.String {
			out["ret"] = result.ValueString
		}
		keys := []string{}
		for k := range state.Store.RawKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		kv := map[string]string{}
		for _, k := range keys {
			kv[k] = hex.EncodeToString(state.Store.RawKeys[k])
		}
		out["store"] = kv
		ok(id, out)

	// ---- Phase 10: DVM address/hash builtins (bech32 differential) --------

	case "bech32_raw":
		addr, err := str(in, "address")
		if err != nil {
			fail(id, err)
			return
		}
		if a, err := rpc.NewAddress(addr); err == nil {
			ok(id, map[string]interface{}{"raw": hex.EncodeToString(a.Compressed())})
		} else {
			ok(id, map[string]interface{}{"raw": ""})
		}

	case "bech32_string":
		rawS, err := str(in, "raw")
		if err != nil {
			fail(id, err)
			return
		}
		rawB, err := unhex(rawS)
		if err != nil || len(rawB) != 33 {
			fail(id, fmt.Errorf("raw must be 33 bytes"))
			return
		}
		p := new(crypto.Point)
		if err := p.DecodeCompressed(rawB); err != nil {
			ok(id, map[string]interface{}{"addr": ""})
			return
		}
		addr := rpc.NewAddressFromKeys(p)
		ok(id, map[string]interface{}{"addr": addr.String()})

	case "bech32_valid":
		addr, err := str(in, "address")
		if err != nil {
			fail(id, err)
			return
		}
		valid := false
		if _, err := rpc.NewAddress(addr); err == nil {
			valid = true
		}
		ok(id, map[string]interface{}{"valid": valid})

	case "hexdecode":
		hx, err := str(in, "hex")
		if err != nil {
			fail(id, err)
			return
		}
		if b, err := hex.DecodeString(hx); err == nil {
			ok(id, map[string]interface{}{"out": hex.EncodeToString(b)})
		} else {
			fail(id, err)
		}

	// ---- Phase 11: real chain tx proof verification ----------------------

	case "tx_extract_verify":
		blobS, err := str(in, "blob")
		if err != nil {
			fail(id, err)
			return
		}
		blob, err := unhex(blobS)
		if err != nil {
			fail(id, err)
			return
		}
		var bl block.Block
		if err := bl.Deserialize(blob); err != nil {
			fail(id, err)
			return
		}
		tx := bl.Miner_TX
		txid := tx.GetHash()
		out := map[string]interface{}{
			"txid": hx(txid[:]),
		}
		scid_map := map[crypto.Hash]int{}
		for t := range tx.Payloads {
			p := &tx.Payloads[t]
			s := &p.Statement
			pk := []string{}
			for _, k := range s.Publickeylist_compressed {
				pk = append(pk, hx(k[:]))
			}
			cln := []string{}
			for _, pt := range s.CLn {
				cln = append(cln, hx(pt.EncodeCompressed()))
			}
			crn := []string{}
			for _, pt := range s.CRn {
				crn = append(crn, hx(pt.EncodeCompressed()))
			}
			c := []string{}
			for _, pt := range s.C {
				c = append(c, hx(pt.EncodeCompressed()))
			}
			index := scid_map[p.SCID]
			verified := p.Proof.Verify(p.SCID, index, s, txid, p.BurnValue)
			out["payload"] = map[string]interface{}{
				"scid":        hx(p.SCID[:]),
				"scid_index":  index,
				"burn":        fmt.Sprintf("%d", p.BurnValue),
				"publickeys":  pk,
				"cln":         cln,
				"crn":         crn,
				"c":           c,
				"d":           hx(s.D.EncodeCompressed()),
				"roothash":    hx(s.Roothash[:]),
				"fees":        fmt.Sprintf("%d", s.Fees),
				"proof":       hx(crypto.OracleProofSerialize(p.Proof)),
				"verified":    verified,
			}
			scid_map[p.SCID] = index + 1
		}
		ok(id, out)

	// ---- Phase 12: graviton tree (state DB) -------------------------------

	case "grav_put":
		tree, err := gravTree(must(in, "tree"))
		if err != nil {
			fail(id, err)
			return
		}
		key, err := unhex(must(in, "key"))
		if err != nil {
			fail(id, err)
			return
		}
		val, err := unhex(must(in, "value"))
		if err != nil {
			fail(id, err)
			return
		}
		tree.Put(key, val)
		h, err := tree.Hash()
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"hash": hex.EncodeToString(h[:])})

	case "grav_delete":
		tree, err := gravTree(must(in, "tree"))
		if err != nil {
			fail(id, err)
			return
		}
		key, err := unhex(must(in, "key"))
		if err != nil {
			fail(id, err)
			return
		}
		tree.Delete(key)
		h, err := tree.Hash()
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"hash": hex.EncodeToString(h[:])})

	case "grav_get":
		tree, err := gravTree(must(in, "tree"))
		if err != nil {
			fail(id, err)
			return
		}
		key, err := unhex(must(in, "key"))
		if err != nil {
			fail(id, err)
			return
		}
		v, err := tree.Get(key)
		if err != nil {
			ok(id, map[string]interface{}{"found": false})
			return
		}
		ok(id, map[string]interface{}{"found": true, "value": hex.EncodeToString(v)})

	// ---- Phase 13: chain state transitions (block -> balance tree) -------

	case "grav_register":
		// register an address with a zero balance: ElGamal{Left: pk, Right: G}
		tree, err := gravTree(must(in, "tree"))
		if err != nil {
			fail(id, err)
			return
		}
		addr, err := unhex(must(in, "address"))
		if err != nil || len(addr) != 33 {
			fail(id, fmt.Errorf("bad address"))
			return
		}
		var acckey crypto.Point
		if err := acckey.DecodeCompressed(addr); err != nil {
			fail(id, err)
			return
		}
		zerobalance := crypto.ConstructElGamal(acckey.G1(), crypto.ElGamal_BASE_G)
		nb := crypto.NonceBalance{NonceHeight: 0, Balance: zerobalance}
		tree.Put(addr, nb.Serialize())
		ok(id, map[string]interface{}{"registered": true})

	case "chain_reward":
		height, err := strconv.ParseUint(must(in, "height"), 10, 64)
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{"reward": fmt.Sprintf("%d", blockchain.OracleCalcBlockReward(height))})

	case "k0_floor":
		// K0 Fix B1 decision rule (Go reference): reject NORMAL/BURN txs
		// with ringsize < 4 from the fork height onward. Calls the REAL
		// exported function; the fork height is overridable per-request so
		// the differential vectors can sweep the boundary (config default:
		// mainnet 7.6M / testnet 0).
		height, err := parseUint(in, "height")
		if err != nil {
			fail(id, err)
			return
		}
		ts, err := parseUint(in, "txtype")
		if err != nil {
			fail(id, err)
			return
		}
		rs, err := parseUint(in, "ringsize")
		if err != nil {
			fail(id, err)
			return
		}
		if ts > 5 { // max TransactionType = SC_TX
			fail(id, fmt.Errorf("unknown txtype %d", ts))
			return
		}
		if rs == 0 || rs > 128 {
			fail(id, fmt.Errorf("ringsize %d out of range 1..=128", rs))
			return
		}
		if f := optionalStr(in, "floor", ""); f != "" {
			floor, ferr := parseUint(in, "floor")
			if ferr != nil {
				fail(id, ferr)
				return
			}
			orig := globals.Config.K0_MIN_RING4_HEIGHT
			globals.Config.K0_MIN_RING4_HEIGHT = int64(floor)
			rej := blockchain.K0RingSizeFloorReject(height, transaction.TransactionType(ts), rs)
			globals.Config.K0_MIN_RING4_HEIGHT = orig
			ok(id, map[string]interface{}{"reject": rej})
			return
		}
		ok(id, map[string]interface{}{"reject": blockchain.K0RingSizeFloorReject(height, transaction.TransactionType(ts), rs)})

	case "b2_reject":
		// K0 Fix B2 decision rules (Go reference):
		//   install: ring-2 SC_INSTALL of a no-SIGNER contract, post-fork -> reject
		//   call:    ring-2 SC_CALL to a NoSigner-bit contract -> reject
		// Pure decision functions (OracleK0B2InstallReject / CallReject) —
		// the differential compares the verdicts against the Rust mirror.
		height, err := parseUint(in, "height")
		if err != nil {
			fail(id, err)
			return
		}
		ringsize, err := parseUint(in, "ringsize")
		if err != nil {
			fail(id, err)
			return
		}
		floor := uint64(7600000)
		if f := optionalStr(in, "floor", ""); f != "" {
			if fl, ferr := parseUint(in, "floor"); ferr == nil {
				floor = fl
			}
		}
		if ringsize == 0 || ringsize > 128 {
			fail(id, fmt.Errorf("ringsize %d out of range 1..=128", ringsize))
			return
		}
		if floor == 0 {
			fail(id, fmt.Errorf("floor must be > 0"))
			return
		}
		usesSigner, err := strictBool(in, "uses_signer")
		if err != nil {
			fail(id, err)
			return
		}
		noSigner, err := strictBool(in, "no_signer")
		if err != nil {
			fail(id, err)
			return
		}
		ok(id, map[string]interface{}{
			"install_reject": blockchain.OracleK0B2InstallReject(height, floor, ringsize, usesSigner),
			"call_reject":    blockchain.OracleK0B2CallReject(ringsize, noSigner),
		})

	case "chain_miner_tx":
		// process_miner_transaction on a JSON-specified block, using the
		// persistent graviton tree "B" (pre-populated by grav_put so the
		// miniblock miners are registered under their hash-aligned keys).
		genesis, _ := strconv.ParseBool(optionalStr(in, "genesis", "false"))
		fees, _ := strconv.ParseUint(optionalStr(in, "fees", "0"), 10, 64)
		height, _ := strconv.ParseUint(optionalStr(in, "height", "0"), 10, 64)
		minerAddr, err := unhex(must(in, "miner_address"))
		if err != nil || len(minerAddr) != 33 {
			fail(id, fmt.Errorf("bad miner_address"))
			return
		}
		minerValue, _ := strconv.ParseUint(optionalStr(in, "miner_value", "0"), 10, 64)
		bt, err := gravTree("B")
		if err != nil {
			fail(id, err)
			return
		}
		// build the block
		var bl block.Block
		bl.Miner_TX.Version = 1
		bl.Miner_TX.TransactionType = transaction.COINBASE
		copy(bl.Miner_TX.MinerAddress[:], minerAddr)
		bl.Miner_TX.Value = minerValue
		// miniblocks from JSON
		var mbls []block.MiniBlock
		if raw, ok := in["miniblocks"]; ok {
			json.Unmarshal(raw, &mbls)
		}
		bl.MiniBlocks = mbls
		blockchain.OracleProcessMinerTx(&bl, genesis, bt, fees, height)
		h, _ := bt.Hash()
		ok(id, map[string]interface{}{"hash": hex.EncodeToString(h[:])})

	// ---- Phase 14: process_transaction (balance moves) --------------------

	case "chain_tx":
		// apply process_transaction on the shared "B" tree:
		// 1. register each ring member (from JSON publickeylist) with a zero
		//    balance if not present
		// 2. build the tx, serialize+deserialize roundtrip (fills the in-memory
		//    Publickeylist_pointers — Go process_transaction reads them)
		// 3. process_transaction -> return tree root + fees
		height, _ := strconv.ParseUint(optionalStr(in, "height", "0"), 10, 64)
		bt, err := gravTree("B")
		if err != nil {
			fail(id, err)
			return
		}
		// register ring keys from JSON
		if payRaw, ok := in["payloads"]; ok {
			var payList []json.RawMessage
			if err := json.Unmarshal(payRaw, &payList); err != nil {
				fail(id, err)
				return
			}
			for _, pj := range payList {
				var pin map[string]json.RawMessage
				if err := json.Unmarshal(pj, &pin); err != nil {
					fail(id, err)
					return
				}
				stmtIn, ok := pin["statement"]
				if !ok {
					continue
				}
				var sim map[string]json.RawMessage
				if err := json.Unmarshal(stmtIn, &sim); err != nil {
					fail(id, err)
					return
				}
				pkRaw, ok := sim["publickeylist"]
				if !ok {
					continue
				}
				var pkList []string
				if err := json.Unmarshal(pkRaw, &pkList); err != nil {
					fail(id, err)
					return
				}
				for _, pkS := range pkList {
					pkB, err := unhex(pkS)
					if err != nil || len(pkB) != 33 {
						fail(id, fmt.Errorf("bad pk"))
						return
					}
					if _, err := bt.Get(pkB); err != nil {
						var acckey crypto.Point
						if err := acckey.DecodeCompressed(pkB); err != nil {
							fail(id, err)
							return
						}
						zerobalance := crypto.ConstructElGamal(acckey.G1(), crypto.ElGamal_BASE_G)
						nb := crypto.NonceBalance{NonceHeight: 0, Balance: zerobalance}
						bt.Put(pkB, nb.Serialize())
					}
				}
			}
		}
		tx, err := txFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
		// roundtrip to fill Publickeylist_pointers (identical bytes both sides)
		ser := tx.Serialize()
		var tx2 transaction.Transaction
		if err := tx2.Deserialize(ser); err != nil {
			fail(id, err)
			return
		}
		fees := blockchain.OracleProcessTx(map[crypto.Hash]*graviton.Tree{}, tx2, bt, height)
		h, _ := bt.Hash()
		ok(id, map[string]interface{}{"hash": hex.EncodeToString(h[:]), "fees": fmt.Sprintf("%d", fees)})

	case "chain_block":
		// apply a full block: miner_tx (with hash-aligned miniblocks) then
		// the block's txs sequentially on the shared "B" tree
		height, _ := strconv.ParseUint(optionalStr(in, "height", "0"), 10, 64)
		fees, _ := strconv.ParseUint(optionalStr(in, "fees", "0"), 10, 64)
		bt, err := gravTree("B")
		if err != nil {
			fail(id, err)
			return
		}
		minerAddr, err := unhex(must(in, "miner_address"))
		if err != nil || len(minerAddr) != 33 {
			fail(id, fmt.Errorf("bad miner_address"))
			return
		}
		var bl block.Block
		bl.Miner_TX.Version = 1
		bl.Miner_TX.TransactionType = transaction.COINBASE
		copy(bl.Miner_TX.MinerAddress[:], minerAddr)
		bl.Miner_TX.Value = 0
		var mbls []block.MiniBlock
		if raw, ok := in["miniblocks"]; ok {
			json.Unmarshal(raw, &mbls)
		}
		bl.MiniBlocks = mbls
		blockchain.OracleProcessMinerTx(&bl, false, bt, fees, height)
		// then the txs (same JSON as chain_tx)
		if payRaw, ok := in["payloads"]; ok {
			var payList []json.RawMessage
			json.Unmarshal(payRaw, &payList)
			for _, pj := range payList {
				var pin map[string]json.RawMessage
				json.Unmarshal(pj, &pin)
				stmtIn, _ := pin["statement"]
				var sim map[string]json.RawMessage
				json.Unmarshal(stmtIn, &sim)
				pkRaw, _ := sim["publickeylist"]
				var pkList []string
				json.Unmarshal(pkRaw, &pkList)
				for _, pkS := range pkList {
					pkB, _ := unhex(pkS)
					if _, err := bt.Get(pkB); err != nil {
						var acckey crypto.Point
						if err := acckey.DecodeCompressed(pkB); err == nil {
							zerobalance := crypto.ConstructElGamal(acckey.G1(), crypto.ElGamal_BASE_G)
							nb := crypto.NonceBalance{NonceHeight: 0, Balance: zerobalance}
							bt.Put(pkB, nb.Serialize())
						}
					}
				}
				var single = map[string]json.RawMessage{}
				for k, v := range in {
					single[k] = v
				}
				single["payloads"] = json.RawMessage(fmt.Sprintf("[%s]", string(pj)))
				tx, err := txFromIn(single)
				if err != nil {
					fail(id, err)
					return
				}
				ser := tx.Serialize()
				var tx2 transaction.Transaction
				if err := tx2.Deserialize(ser); err != nil {
					fail(id, err)
					return
				}
				blockchain.OracleProcessTx(map[crypto.Hash]*graviton.Tree{}, tx2, bt, height)
			}
		}
		h, _ := bt.Hash()
		ok(id, map[string]interface{}{"hash": hex.EncodeToString(h[:])})

	// ---- Phase 15: SC install/call (process_transaction_sc) ---------------

	case "chain_sc_debug":
		// deserialize + report SCDATA contents (debug the install path)
		blobS, err := str(in, "blob")
		if err != nil {
			fail(id, err)
			return
		}
		blob, err := unhex(blobS)
		if err != nil {
			fail(id, err)
			return
		}
		var tx transaction.Transaction
		if err := tx.Deserialize(blob); err != nil {
			fail(id, err)
			return
		}
		args := []string{}
		for _, a := range tx.SCDATA {
			args = append(args, fmt.Sprintf("%s=%v(%v)", a.Name, a.Value, a.DataType))
		}
		has := tx.SCDATA.Has(rpc.SCACTION, rpc.DataUint64)
		ok(id, map[string]interface{}{"scdata_len": len(tx.SCDATA), "args": args, "has_action": has})

	case "chain_sc_install":
		// install a smart contract: SCDATA with SCACTION=SC_INSTALL + SCCODE
		// The tx carries the code; process_transaction_sc parses + installs
		// (writes SC_Code_Key + meta into the SC data/meta trees), runs
		// Initialize/InitializePrivate. Returns the SC data tree root + gas.
		blobS, err := str(in, "blob")
		if err != nil {
			fail(id, err)
			return
		}
		blob, err := unhex(blobS)
		if err != nil {
			fail(id, err)
			return
		}
		var tx transaction.Transaction
		if err := tx.Deserialize(blob); err != nil {
			fail(id, err)
			return
		}
		height, _ := strconv.ParseUint(optionalStr(in, "height", "0"), 10, 64)
		// K0 Fix B2: the floor override lets vectors sweep pre/post-fork
		// installs (NoSigner bit set only from the fork height). The
		// reference's install path keys off globals.Config.K0_MIN_RING4_HEIGHT.
		if f := optionalStr(in, "k0_floor", ""); f != "" {
			if fl, ferr := strconv.ParseInt(f, 10, 64); ferr == nil {
				globals.Config.K0_MIN_RING4_HEIGHT = fl
			}
		}
		store, _ := graviton.NewMemStore()
		ss, _ := store.LoadSnapshot(0)
		cache := map[crypto.Hash]*graviton.Tree{}
		bt, _ := gravTree("B") // SHARED persistent tree (harness pre-registers)
		mt, _ := ss.GetTree(config.SC_META)
		txid := tx.GetHash()
		scid := txid
		// expand the tx against a balance tree with the ring keys registered
		// (the real chain expands before SC processing)
		chain := &blockchain.Blockchain{}
		_ = chain
		// register ring keys on bt
		for t := range tx.Payloads {
			for i := 0; i < int(tx.Payloads[t].Statement.RingSize); i++ {
				key_pointer := tx.Payloads[t].Statement.Publickeylist_pointers[i*int(tx.Payloads[t].Statement.Bytes_per_publickey) : (i+1)*int(tx.Payloads[t].Statement.Bytes_per_publickey)]
				if _, kc, _, err := bt.GetKeyValueFromHash(key_pointer); err == nil {
					if _, err := bt.Get(kc); err != nil {
						var acckey crypto.Point
						if err := acckey.DecodeCompressed(kc); err == nil {
							zb := crypto.ConstructElGamal(acckey.G1(), crypto.ElGamal_BASE_G)
							nb := crypto.NonceBalance{NonceHeight: 0, Balance: zb}
							bt.Put(kc, nb.Serialize())
						}
					}
				}
			}
		}
		// Expand the tx (needs the balance tree at tx.BLID — we use bt)
		// Go's Expand_Transaction_NonCoinbase requires chain state; emulate
		// it by loading the statement keys directly from the pointers:
		// build Publickeylist_compressed from the tree lookups.
		for t := range tx.Payloads {
			st := &tx.Payloads[t].Statement
			st.Publickeylist_compressed = st.Publickeylist_compressed[:0]
			for i := 0; i < int(st.RingSize); i++ {
				key_pointer := st.Publickeylist_pointers[i*int(st.Bytes_per_publickey) : (i+1)*int(st.Bytes_per_publickey)]
				if _, kc, _, err := bt.GetKeyValueFromHash(key_pointer); err == nil {
					var pc [33]byte
					copy(pc[:], kc)
					st.Publickeylist_compressed = append(st.Publickeylist_compressed, pc)
				}
			}
		}
		// re-serialize to sync Statement fields the SC path needs
		ser2 := tx.Serialize()
		var tx3 transaction.Transaction
		if err := tx3.Deserialize(ser2); err != nil {
			fail(id, err)
			return
		}
		tx = tx3
		// register the signer
		signer := [33]byte{}
		if s, err := unhex(optionalStr(in, "signer", "")); err == nil && len(s) == 33 {
			copy(signer[:], s)
		} else if len(tx.Payloads) > 0 && len(tx.Payloads[0].Statement.Publickeylist_compressed) > 0 {
			signer = tx.Payloads[0].Statement.Publickeylist_compressed[0]
		}
		if _, err := bt.Get(signer[:]); err != nil {
			var acckey crypto.Point
			if err := acckey.DecodeCompressed(signer[:]); err == nil {
				zb := crypto.ConstructElGamal(acckey.G1(), crypto.ElGamal_BASE_G)
				nb := crypto.NonceBalance{NonceHeight: 0, Balance: zb}
				bt.Put(signer[:], nb.Serialize())
			}
		}
		gas, err, dr, mr, clen := blockchain.OracleProcessTxSCDebug(cache, ss, height, height, 0, txid, tx, bt, mt)
		if err != nil {
			ok(id, map[string]interface{}{"err": err.Error(), "gas": fmt.Sprintf("%d", gas),
				"cache_len": clen, "data_root": hex.EncodeToString(dr), "meta_root": hex.EncodeToString(mr)})
			return
		}
		hh, _ := bt.Hash()
		ok(id, map[string]interface{}{"scid": hex.EncodeToString(scid[:]), "gas": fmt.Sprintf("%d", gas),
			"data_root": hex.EncodeToString(dr), "balance_root": hex.EncodeToString(hh[:]),
			"cache_len": clen, "meta_root": hex.EncodeToString(mr)})

	default:
		fail(id, fmt.Errorf("unknown op %q", op))
	}
}

var gravtrees = map[string]*graviton.Tree{}

func gravTree(name string) (*graviton.Tree, error) {
	if t, ok := gravtrees[name]; ok {
		return t, nil
	}
	store, err := graviton.NewMemStore()
	if err != nil {
		return nil, err
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		return nil, err
	}
	t, err := ss.GetTree(name)
	if err != nil {
		return nil, err
	}
	gravtrees[name] = t
	return t, nil
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			b, _ := json.Marshal(Response{ID: -1, OK: false, Err: fmt.Sprintf("bad request json: %v", err)})
			fmt.Println(string(b))
			continue
		}
		handle(req.ID, req.Op, req.In)
	}
}
