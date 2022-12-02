package verifier

import (
	"crypto/sha256"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/crypto"
	"github.com/drand/kyber"
)

// Verifier allows verifying the beacons signature based on a scheme.
type Verifier struct {
	// scheme holds a set of values the verifying process will use to act in specific ways, regarding signature verification, etc
	*crypto.Scheme
}

func NewVerifier(sch *crypto.Scheme) *Verifier {
	return &Verifier{Scheme: sch}
}

// DigestMessage returns a slice of bytes as the message to sign or to verify
// alongside a beacon signature.
func (v *Verifier) DigestMessage(currRound uint64, prevSig []byte) []byte {
	h := sha256.New()

	if v.IsPreviousSigSignificant {
		_, _ = h.Write(prevSig)
	}
	_, _ = h.Write(chain.RoundToBytes(currRound))
	return h.Sum(nil)
}

// VerifyBeacon returns an error if the given beacon does not verify given the
// public key. The public key "point" can be obtained from the
// `key.DistPublic.Key()` method. The distributed public is the one written in
// the configuration file of the network.
func (v *Verifier) VerifyBeacon(b chain.Beacon, pubkey kyber.Point) error {
	prevSig := b.PreviousSig
	round := b.Round

	msg := v.DigestMessage(round, prevSig)

	return v.Scheme.ThresholdScheme.VerifyRecovered(pubkey, msg, b.Signature)
}

// IsPrevSigMeaningful returns whether the verifier needs a previous signature or not to verify the current one
func (v *Verifier) IsPrevSigMeaningful() bool {
	return v.IsPreviousSigSignificant
}
