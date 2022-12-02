package gocrypt

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"testing"
)

type DinePackage struct {
	IV   string `json:"iv"`
	DATA string `json:"data"`
}

func GenRandomBytes(length int) (blk []byte, err error) {
	ran_str := make([]byte, length)
	for i := 0; i < length; i++ {
		ran_str[i] = byte(65 + rand.Intn(25))
	}
	return ran_str, nil
}

// 确保秘钥合规
func CheckKeyIsVildate(aesKey string) bool {
	return len(aesKey) == 16
}

func DecodeToPackage(realInfo string, aesKey string) (*DinePackage, error) {
	if CheckKeyIsVildate(aesKey) {
		return nil, fmt.Errorf("秘钥错误！ AES_KEY ERROR !")
	}
	iv, err := GenRandomBytes(16)
	if err != nil {
		return nil, err
	}
	aesUtil, err := NewAES(
		[]byte(aesKey),
		iv,
		Options{
			Mode:    MODE_CFB,
			Padding: PAD_ISO10126,
		},
	)
	if err != nil {
		return nil, err
	}

	encedBytes, err := aesUtil.Encrypt([]byte(realInfo))
	if err != nil {
		return nil, err
	}

	b64Str := base64.StdEncoding.EncodeToString(encedBytes)
	if err != nil {
		return nil, err
	}
	return &DinePackage{
		IV:   string(iv),
		DATA: b64Str,
	}, nil
}
func DecodeFromPackage(dp *DinePackage, aesKey string) ([]byte, error) {
	if CheckKeyIsVildate(aesKey) {
		return nil, fmt.Errorf("秘钥错误！ AES_KEY ERROR !")
	}
	aesUtil, err := NewAES(
		[]byte(aesKey),
		[]byte(dp.IV),
		Options{
			Mode:    MODE_CFB,
			Padding: PAD_ISO10126,
		},
	)
	if err != nil {
		return nil, err
	}

	aseEncrypedBytes, err := base64.StdEncoding.DecodeString(dp.DATA)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := aesUtil.Decrypt(aseEncrypedBytes)
	if err != nil {
		return nil, err
	}
	return decodedBytes, nil
}

func TestTheAesDDD(t *testing.T) {
	aa, err := DecodeFromPackage(
		&DinePackage{
			IV:   `11hnpuuww00glmy1`,
			DATA: `XWEFKDLZu/zmKONDw3F94ZzYlPotgAan9UI700jNfWhZhk/ZPVhnGMUjR6zTLMhz`,
		},
		`IPWV7nuYQAKxKZq0z0uiKPJvXRXdp9FC`,
	)
	fmt.Println(err)
	fmt.Println(string(aa))
	fmt.Println(string(aa))
	if string(aa) != `{"we": "你好", "timestamp": 1654933089828}` {
		t.Errorf("错误")
	}

}

func TestTheAesDDD1111(t *testing.T) {
	aa, err := DecodeFromPackage(
		&DinePackage{
			IV:   `ayf4htmfhx5x0gig`,
			DATA: `v+MoWnTlsLscxMnYEecc1Q==`,
		},
		`IPWV7nuYQAKxKZq0z0uiKPJvXRXdp9FC`,
	)
	fmt.Println(err)
	fmt.Println(string(aa))
	fmt.Println(string(aa))
	if string(aa) != `{"we": 100}` {
		t.Errorf("错误")
	}
}
