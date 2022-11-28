package vault

import (
	"sync"

	"github.com/drand/drand/crypto"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/key"
	"github.com/drand/kyber/share"
)

// CryptoSafe holds the cryptographic information to generate a partial beacon
type CryptoSafe interface {
	// SignPartial returns the partial signature
	SignPartial(msg []byte) ([]byte, error)
}

// Vault stores the information necessary to validate partial beacon, full
// beacons and to sign new partial beacons (it implements CryptoSafe interface).
// Vault is thread safe when using the methods.
type Vault struct {
	sync.Mutex
	crypto.Scheme
	// current share of the node
	share *key.Share
	// public polynomial to verify a partial beacon
	pub *share.PubPoly
	// chian info to verify final random beacon
	chain *chain.Info
	// to know the threshold, transition time etc
	group *key.Group
}

func NewVault(currentGroup *key.Group, ks *key.Share) *Vault {
	return &Vault{
		Scheme: currentGroup.Scheme,
		chain:  chain.NewChainInfo(currentGroup),
		share:  ks,
		pub:    currentGroup.PublicKey.PubPoly(),
		group:  currentGroup,
	}
}

// GetGroup returns the current group
func (c *Vault) GetGroup() *key.Group {
	c.Lock()
	defer c.Unlock()
	return c.group
}

func (c *Vault) GetPub() *share.PubPoly {
	c.Lock()
	defer c.Unlock()
	return c.pub
}

func (c *Vault) GetInfo() *chain.Info {
	c.Lock()
	defer c.Unlock()
	return c.chain
}

// SignPartial implemements the CryptoSafe interface
func (c *Vault) SignPartial(msg []byte) ([]byte, error) {
	c.Lock()
	defer c.Unlock()
	return c.Scheme.ThresholdScheme.Sign(c.share.PrivateShare(), msg)
}

// Index returns the index of the share
func (c *Vault) Index() int {
	c.Lock()
	defer c.Unlock()
	return c.share.Share.I
}

func (c *Vault) SetInfo(newGroup *key.Group, ks *key.Share) {
	c.Lock()
	defer c.Unlock()
	c.share = ks
	c.group = newGroup
	c.pub = newGroup.PublicKey.PubPoly()
	// chain info is constant
}
