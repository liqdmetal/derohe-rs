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
	"strings"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
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
	// witness
	skHex, err := str(in, "secretkey")
	if err != nil {
		return nil, nil, err
	}
	sk, err := b32(skHex)
	if err != nil {
		return nil, nil, err
	}
	rHex, err := str(in, "r")
	if err != nil {
		return nil, nil, err
	}
	rBig, err := b32(rHex)
	if err != nil {
		return nil, nil, err
	}
	trS, err := str(in, "transfer")
	if err != nil {
		return nil, nil, err
	}
	var transfer, balance uint64
	if _, err := fmt.Sscanf(trS, "%d", &transfer); err != nil {
		return nil, nil, err
	}
	balS, err := str(in, "balance")
	if err != nil {
		return nil, nil, err
	}
	if _, err := fmt.Sscanf(balS, "%d", &balance); err != nil {
		return nil, nil, err
	}
	idxRaw, ok := in["index"]
	if !ok {
		return nil, nil, fmt.Errorf("missing index")
	}
	var idx []int
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		return nil, nil, err
	}
	w := &crypto.Witness{SecretKey: sk, R: rBig, TransferAmount: transfer, Balance: balance, Index: idx}
	return s, w, nil
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
		s, w, err := statementFromIn(in)
		if err != nil {
			fail(id, err)
			return
		}
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
		proof := crypto.OracleGenerateProof(scid, scidIdx, s, w, u, txid, burn)
		ser := crypto.OracleProofSerialize(proof)
		nonce := crypto.OracleProofNonce(proof)
		parity := crypto.OracleProofParity(proof)
		ok(id, map[string]interface{}{
			"proof": hx(ser),
			"nonce": hx(nonce[:]),
			"parity": parity,
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

	case "proof_verify":
		s, _, err := statementFromIn(in)
		if err != nil {
			fail(id, err)
			return
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
		verified, _ := crypto.OracleVerifyProof(crypto.ZEROHASH, scid, scidIdx, s, proof, txid, burn)
		ok(id, map[string]interface{}{"verified": verified})

	default:
		fail(id, fmt.Errorf("unknown op %q", op))
	}
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
