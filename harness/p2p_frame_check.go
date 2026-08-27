package main

import (
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type Common_Struct struct {
	Height       int64    `cbor:"HEIGHT"`
	TopoHeight   int64    `cbor:"THEIGHT"`
	StableHeight int64    `cbor:"SHEIGHT"`
	StateHash    [32]byte `cbor:"STATE"`
	Top_Version  uint64   `cbor:"HF"`
}

type Chain_Request_Struct struct {
	Common      Common_Struct `cbor:"COMMON"`
	Block_list  [][32]byte    `cbor:"BLIST"`
	TopoHeights []int64       `cbor:"TOPO"`
}

type RequestResponse struct {
	Method string `cbor:"M"`
	Seq    uint64 `cbor:"S"`
	Error  string `cbor:"E"`
}

func main() {
	hdr := RequestResponse{Method: "Peer.Chain", Seq: 1}
	body := Chain_Request_Struct{Common: Common_Struct{}, Block_list: [][32]byte{}, TopoHeights: []int64{}}
	hb, _ := cbor.Marshal(hdr)
	bb, _ := cbor.Marshal(body)
	var fl [4]byte
	binary.LittleEndian.PutUint32(fl[:], uint32(len(hb)))
	fmt.Printf("HDR FRAME: %s%s\n", fl[:], hb)
	binary.LittleEndian.PutUint32(fl[:], uint32(len(bb)))
	fmt.Printf("BODY FRAME: %s%s\n", fl[:], bb)
	fmt.Printf("HDR CBOR hex: %x\n", hb)
	fmt.Printf("BODY CBOR hex: %x\n", bb)
}
