package crypto

import (
	"crypto/cipher"

	"github.com/drand/kyber"

	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/sign"

	// FIXME package github.com/drand/kyber/sign/bls is deprecated: This version is vulnerable to
	// rogue public-key attack and the new version of the protocol should be used to make sure a
	// signature aggregate cannot be verified by a forged key. You can find the protocol in kyber/sign/bdn.
	// Note that only the aggregation is broken against the attack and a later version will merge bls and asmbls.
	//nolint:staticcheck
	signBls "github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/schnorr"
	"github.com/drand/kyber/sign/tbls"

	"github.com/drand/kyber/util/random"
	"golang.org/x/crypto/blake2b"

	"hash"
)

type Scheme struct {
	// The name of the scheme
	Name string
	// whether this is a "chained" or "unchained" scheme
	IsPreviousSigSignificant bool
	// SigGroup is the group used to create the signatures; it must always be
	// different from the KeyGroup: G1 key group and G2 sig group or G1 sig group and G2 keygroup.
	SigGroup kyber.Group
	// KeyGroup is the group used to create the keys
	KeyGroup kyber.Group
	// ThresholdScheme is the signature scheme used, defining over which curve the signature
	// and keys respectively are.
	ThresholdScheme sign.ThresholdScheme
	// AuthScheme is the signature scheme used to identify public identities
	AuthScheme sign.AggregatableScheme
	// DKGAuthScheme is the signature scheme used to authenticate packets during broadcast in a DKG
	DKGAuthScheme sign.Scheme
	// Pairing is the underlying pairing Suite.
	Pairing pairing.Suite
	// the hash function used by this scheme
	HashFunc func() hash.Hash
}

type schnorrSuite struct {
	kyber.Group
}

func (s *schnorrSuite) RandomStream() cipher.Stream {
	return random.New()
}

//nolint:dupl
func NewPedersenBLSChained() (cs *Scheme) {
	var Pairing = bls.NewBLS12381Suite()
	var KeyGroup = Pairing.G1()
	var SigGroup = Pairing.G2()
	var ThresholdScheme = tbls.NewThresholdSchemeOnG2(Pairing)
	var AuthScheme = signBls.NewSchemeOnG2(Pairing)
	var DKGAuthScheme = schnorr.NewScheme(&schnorrSuite{KeyGroup})
	var HashFunc = func() hash.Hash { h, _ := blake2b.New256(nil); return h }

	return &Scheme{
		Name:                     "pedersen-bls-chained",
		IsPreviousSigSignificant: true,
		SigGroup:                 SigGroup,
		KeyGroup:                 KeyGroup,
		ThresholdScheme:          ThresholdScheme,
		AuthScheme:               AuthScheme,
		DKGAuthScheme:            DKGAuthScheme,
		Pairing:                  Pairing,
		HashFunc:                 HashFunc,
	}
}

//nolint:dupl
func NewPedersenBLSUnchained() (cs *Scheme) {
	var Pairing = bls.NewBLS12381Suite()
	var KeyGroup = Pairing.G1()
	var SigGroup = Pairing.G2()
	var ThresholdScheme = tbls.NewThresholdSchemeOnG2(Pairing)
	var AuthScheme = signBls.NewSchemeOnG2(Pairing)
	var DKGAuthScheme = schnorr.NewScheme(&schnorrSuite{KeyGroup})
	var HashFunc = func() hash.Hash { h, _ := blake2b.New256(nil); return h }

	return &Scheme{
		Name:                     "pedersen-bls-unchained",
		IsPreviousSigSignificant: false,
		SigGroup:                 SigGroup,
		KeyGroup:                 KeyGroup,
		ThresholdScheme:          ThresholdScheme,
		AuthScheme:               AuthScheme,
		DKGAuthScheme:            DKGAuthScheme,
		Pairing:                  Pairing,
		HashFunc:                 HashFunc,
	}
}

//nolint:dupl
func NewPedersenBLSUnchainedSwapped() (cs *Scheme) {
	var Pairing = bls.NewBLS12381Suite()
	var KeyGroup = Pairing.G2()
	var SigGroup = Pairing.G1()
	var ThresholdScheme = tbls.NewThresholdSchemeOnG1(Pairing)
	var AuthScheme = signBls.NewSchemeOnG1(Pairing)
	var DKGAuthScheme = schnorr.NewScheme(&schnorrSuite{KeyGroup})
	var HashFunc = func() hash.Hash { h, _ := blake2b.New256(nil); return h }

	return &Scheme{
		Name:                     "pedersen-bls-unchained-swapped",
		IsPreviousSigSignificant: false,
		SigGroup:                 SigGroup,
		KeyGroup:                 KeyGroup,
		ThresholdScheme:          ThresholdScheme,
		AuthScheme:               AuthScheme,
		DKGAuthScheme:            DKGAuthScheme,
		Pairing:                  Pairing,
		HashFunc:                 HashFunc,
	}
}

func SchemeFromName(schemeName string) (cs *Scheme) {
	switch schemeName {
	case "pedersen-bls-chained":
		return NewPedersenBLSChained()
	case "pedersen-bls-unchained":
		return NewPedersenBLSUnchained()
	case "bls-unchained-shortsig":
		return NewPedersenBLSUnchainedSwapped()
	default:
		return nil
	}
}
