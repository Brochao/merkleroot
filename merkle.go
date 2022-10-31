package merkleroot

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

type MerkleNode struct {
	Value string
	Left  *MerkleNode
	Right *MerkleNode
}

// txid: in little-endian
func ConstructMerkleRoot(txids []string) (*MerkleNode, error) {
	//params check
	if len(txids) == 0 {
		return nil, errors.New("txids is empth")
	}

	//begin construct
	var leafNodes []MerkleNode
	for _, txid := range txids {
		var oneLeaf = MerkleNode{Value: txid, Left: nil, Right: nil}
		leafNodes = append(leafNodes, oneLeaf)
	}
	return ConstructMerkleTreeNodes(leafNodes)
}

func ConstructMerkleTreeNodes(nodes []MerkleNode) (*MerkleNode, error) {
	//params check
	if len(nodes) == 0 {
		return nil, errors.New("number of nodes is 0")
	}
	if len(nodes) == 1 {
		return &nodes[0], nil
	}
	if len(nodes) == 2 {
		var root = MerkleNode{}
		var err error
		if root, err = Merge(&nodes[0], &nodes[1]); err != nil {
			return nil, err
		}
		return &root, nil
	}

	var (
		err         error
		nodeAmount  = len(nodes)
		parentNodes []MerkleNode
		left        *MerkleNode
		right       *MerkleNode
	)

	//处理三个及三个以上的节点
	for i := 0; i < nodeAmount; i += 2 {
		var parentNode = MerkleNode{}
		left = &nodes[i]
		if i == nodeAmount-1 { //最后一个单独的节点
			right = &nodes[i]
		} else {
			right = &nodes[i+1]
		}
		if parentNode, err = Merge(left, right); err != nil {
			return nil, err
		}
		parentNodes = append(parentNodes, parentNode)
	}
	return ConstructMerkleTreeNodes(parentNodes)
}

func Merge(left *MerkleNode, right *MerkleNode) (MerkleNode, error) {
	var (
		parentNode = MerkleNode{Value: "", Left: left, Right: right}
		data       []byte
		err        error
		leftBytes  []byte
		rightBytes []byte
	)
	//计算的时候txid从BigEdian转变成LittleEdian
	if leftBytes, err = ReverseBigEdianString(left.Value); err != nil {
		return MerkleNode{}, err
	}
	if rightBytes, err = ReverseBigEdianString(right.Value); err != nil {
		return MerkleNode{}, err
	}
	data = append(leftBytes, rightBytes...)

	var parentHash = Sha256AfterSha256(data)

	//用字符串显示时保存为小端
	data = ReverseBytes(parentHash[:])
	parentNode.Value = hex.EncodeToString(data)
	return parentNode, nil
}

//----------

func Sha256AfterSha256(data []byte) [32]byte {
	hash256 := sha256.Sum256(data)
	hash256 = sha256.Sum256(hash256[:])
	return hash256
}

// 把单个uint32类型数据变成大端字节序
func Uint32ToBytes(n uint32) []byte {
	var uint32Bytes [4]byte
	binary.BigEndian.PutUint32(uint32Bytes[:], n)
	return uint32Bytes[:]
}

func ReverseBytes(data []byte) []byte {
	var length = len(data)
	for i := 0; i < length/2; i++ {
		data[i], data[length-1-i] = data[length-1-i], data[i]
	}
	return data
}

func ReverseBigEdianString(data string) ([]byte, error) {
	var (
		ret []byte
		err error
	)
	if ret, err = hex.DecodeString(data); err != nil {
		return nil, err
	}
	ret = ReverseBytes(ret)
	return ret, nil
}
