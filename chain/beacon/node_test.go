package beacon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/drand/drand/crypto"
	verifier2 "github.com/drand/drand/crypto/verifier"
	"github.com/drand/kyber/share/dkg"

	clock "github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/chain/boltdb"
	"github.com/drand/drand/common"
	"github.com/drand/drand/common/scheme"
	"github.com/drand/drand/key"
	"github.com/drand/drand/log"
	"github.com/drand/drand/net"
	pbCommon "github.com/drand/drand/protobuf/common"
	"github.com/drand/drand/protobuf/drand"
	"github.com/drand/drand/test"
	testnet "github.com/drand/drand/test/net"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"
)

// TODO make beacon tests not dependent on scheme.ThresholdScheme

// testBeaconServer implements a barebone service to be plugged in a net.DefaultService
type testBeaconServer struct {
	disable bool
	*testnet.EmptyServer
	h *Handler
}

func (t *testBeaconServer) PartialBeacon(c context.Context, in *drand.PartialBeaconPacket) (*drand.Empty, error) {
	if t.disable {
		return nil, errors.New("disabled server")
	}
	return t.h.ProcessPartialBeacon(c, in)
}

func (t *testBeaconServer) SyncChain(req *drand.SyncRequest, p drand.Protocol_SyncChainServer) error {
	if t.disable {
		return errors.New("disabled server")
	}
	return SyncChain(t.h.l, t.h.chain, req, p)
}

func dkgShares(_ *testing.T, n, t int, sch *crypto.Scheme) ([]*key.Share, []kyber.Point) {
	var priPoly *share.PriPoly
	var pubPoly *share.PubPoly
	var err error
	for i := 0; i < n; i++ {
		pri := share.NewPriPoly(sch.KeyGroup, t, sch.KeyGroup.Scalar().Pick(random.New()), random.New())
		pub := pri.Commit(sch.KeyGroup.Point().Base())
		if priPoly == nil {
			priPoly = pri
			pubPoly = pub
			continue
		}
		priPoly, err = priPoly.Add(pri)
		if err != nil {
			panic(err)
		}
		pubPoly, err = pubPoly.Add(pub)
		if err != nil {
			panic(err)
		}
	}
	shares := priPoly.Shares(n)
	secret, err := share.RecoverSecret(sch.KeyGroup, shares, t, n)
	if err != nil {
		panic(err)
	}
	if !secret.Equal(priPoly.Secret()) {
		panic("secret not equal")
	}
	msg := []byte("Hello world")
	sigs := make([][]byte, n)

	_, commits := pubPoly.Info()
	dkgShares := make([]*key.Share, n)
	for i := 0; i < n; i++ {
		sigs[i], err = sch.ThresholdScheme.Sign(shares[i], msg)
		if err != nil {
			panic(err)
		}
		dkgShares[i] = &key.Share{DistKeyShare: dkg.DistKeyShare{Share: shares[i], Commits: commits}, Scheme: sch}
	}
	sig, err := sch.ThresholdScheme.Recover(pubPoly, msg, sigs, t, n)
	if err != nil {
		panic(err)
	}
	if err = sch.ThresholdScheme.VerifyRecovered(pubPoly.Commit(), msg, sig); err != nil {
		panic(err)
	}
	return dkgShares, commits
}

type node struct {
	index    int // group index
	private  *key.Pair
	shares   *key.Share
	callback func(*chain.Beacon)
	handler  *Handler
	listener net.Listener
	clock    clock.FakeClock
	started  bool
	server   *testBeaconServer
}

type BeaconTest struct {
	paths    []string
	n        int
	thr      int
	beaconID string
	shares   []*key.Share
	period   time.Duration
	group    *key.Group
	privs    []*key.Pair
	dpublic  kyber.Point
	nodes    map[int]*node
	time     clock.FakeClock
	prefix   string
	scheme   *crypto.Scheme
}

func NewBeaconTest(t *testing.T, n, thr int, period time.Duration, genesisTime int64, sch *crypto.Scheme, beaconID string) *BeaconTest {
	prefix := t.TempDir()
	paths := createBoltStores(prefix, n)
	shares, commits := dkgShares(t, n, thr, sch)
	privs, group := test.BatchIdentities(n, sch, beaconID)
	group.Threshold = thr
	group.Period = period
	group.GenesisTime = genesisTime
	group.PublicKey = &key.DistPublic{Coefficients: commits, Scheme: sch}

	bt := &BeaconTest{
		prefix:   prefix,
		n:        n,
		privs:    privs,
		thr:      thr,
		period:   period,
		beaconID: beaconID,
		scheme:   sch,
		paths:    paths,
		shares:   shares,
		group:    group,
		dpublic:  group.PublicKey.PubPoly().Commit(),
		nodes:    make(map[int]*node),
		time:     clock.NewFakeClock(),
	}

	for i := 0; i < n; i++ {
		bt.CreateNode(t, i)
		t.Logf("Creating node %d/%d", i+1, n)
	}
	return bt
}

func (b *BeaconTest) CreateNode(t *testing.T, i int) {
	findShare := func(target int) *key.Share {
		for _, s := range b.shares {
			if s.Share.I == target {
				return s
			}
		}
		panic("we should always get a share")
	}
	priv := b.privs[i]
	knode := b.group.Find(priv.Public)
	if knode == nil {
		panic("we should always get a private key")
	}
	idx := int(knode.Index)
	node := &node{}
	if n, ok := b.nodes[idx]; ok {
		node = n
	}
	node.index = idx
	node.private = priv
	keyShare := findShare(idx)
	node.shares = keyShare

	l := test.Logger(t)
	store, err := boltdb.NewBoltStore(l, b.paths[idx], nil)
	if err != nil {
		panic(err)
	}
	node.clock = clock.NewFakeClockAt(b.time.Now())
	conf := &Config{
		Group:  b.group,
		Public: knode,
		Share:  keyShare,
		Clock:  node.clock,
	}

	logger := log.NewLogger(nil, log.LogDebug).Named("BeaconTest").Named(knode.Addr).Named(fmt.Sprint(idx))
	version := common.GetAppVersion()
	node.handler, err = NewHandler(net.NewGrpcClient(), store, conf, logger, version)
	checkErr(err)
	if node.callback != nil {
		node.handler.AddCallback(priv.Public.Address(), node.callback)
	}

	if node.handler.addr != node.private.Public.Address() {
		panic("createNode address mismatch")
	}

	currSig, err := b.scheme.ThresholdScheme.Sign(node.handler.conf.Share.PrivateShare(), []byte("hello"))
	checkErr(err)
	sigIndex, _ := b.scheme.ThresholdScheme.IndexOf(currSig)
	if sigIndex != idx {
		panic("invalid index")
	}
	b.nodes[idx] = node
	t.Logf("Created NODE index %d --> Listens on %s || Clock pointer %p\n", idx, priv.Public.Address(), b.nodes[idx].handler.conf.Clock)
	for i, n := range b.nodes {
		for j, n2 := range b.nodes {
			if i == j {
				continue
			}
			if n.index == n2.index {
				panic("invalid index setting")
			}
		}
	}
	t.Cleanup(func() {
		t.Log("Stopping node:", idx)
		b.StopBeacon(idx)
		t.Log("Node stopped:", idx)
	})
}

func (b *BeaconTest) ServeBeacon(t *testing.T, i int) {
	j := b.searchNode(i)
	beaconServer := &testBeaconServer{
		h: b.nodes[j].handler,
	}
	b.nodes[j].server = beaconServer
	var err error
	b.nodes[j].listener, err = net.NewGRPCListenerForPrivate(
		context.Background(),
		b.nodes[j].private.Public.Address(),
		"", "",
		beaconServer,
		true)
	if err != nil {
		panic(err)
	}
	t.Logf("Serve Beacon for node %d - %p --> %s\n", j, b.nodes[j].handler, b.nodes[j].private.Public.Address())
	go b.nodes[j].listener.Start()
}

func (b *BeaconTest) StartBeacons(t *testing.T, n int) {
	for i := 0; i < n; i++ {
		b.StartBeacon(t, i, false)
	}

	// give time for go routines to kick off
	for i := 0; i < n; i++ {
		err := b.WaitBeaconToKickoff(t, i)
		require.NoError(t, err)
	}
}
func (b *BeaconTest) StartBeacon(t *testing.T, i int, catchup bool) {
	j := b.searchNode(i)
	b.nodes[j].started = true
	if catchup {
		t.Logf("Start BEACON %s - node pointer %p\n", b.nodes[j].handler.addr, b.nodes[j].handler)
		go b.nodes[j].handler.Catchup()
	} else {
		go b.nodes[j].handler.Start()
	}
}

func (b *BeaconTest) WaitBeaconToKickoff(t *testing.T, i int) error {
	j := b.searchNode(i)
	counter := 0

	for {
		if b.nodes[j].handler.IsRunning() {
			return nil
		}

		counter++
		if counter == 10 {
			return fmt.Errorf("timeout waiting beacon %d to run", i)
		}

		t.Logf("beacon %d is not running yet, waiting some time to ask again...", i)
		time.Sleep(500 * time.Millisecond)
	}
}

func (b *BeaconTest) searchNode(i int) int {
	for j, n := range b.nodes {
		if n.index == i {
			return j
		}
	}
	panic("no such index")
}
func (b *BeaconTest) MoveTime(t *testing.T, timeToMove time.Duration) {
	for _, n := range b.nodes {
		before := n.clock.Now().Unix()
		n.handler.conf.Clock.(clock.FakeClock).Advance(timeToMove)
		t.Logf(" - %d increasing time of node %d - %s (pointer %p)- before: %d - current: %d - pointer clock %p\n",
			time.Now().Unix(),
			n.index,
			n.private.Public.Address(),
			n,
			before,
			n.clock.Now().Unix(),
			n.handler.conf.Clock)
	}
	b.time.Advance(timeToMove)
}

func (b *BeaconTest) StopBeacon(i int) {
	j := b.searchNode(i)
	if n, ok := b.nodes[j]; ok {
		if !n.started {
			return
		}
		n.listener.Stop(context.Background())
		n.handler.Stop()
		n.started = false
	}
	delete(b.nodes, j)
}

func (b *BeaconTest) DisableReception(count int) {
	for i := 0; i < count; i++ {
		b.nodes[i].server.disable = true
	}
}

func (b *BeaconTest) EnableReception(count int) {
	for i := 0; i < count; i++ {
		b.nodes[i].server.disable = false
	}
}

func checkErr(e error) {
	if e != nil {
		panic(e)
	}
}

func createBoltStores(prefix string, n int) []string {
	paths := make([]string, n)
	for i := 0; i < n; i++ {
		paths[i] = path.Join(prefix, fmt.Sprintf("drand-%d", i))
		if err := os.MkdirAll(paths[i], 0755); err != nil {
			panic(err)
		}
	}
	return paths
}

func checkWait(t *testing.T, counter *sync.WaitGroup) {
	var doneCh = make(chan bool, 1)
	go func() {
		counter.Wait()
		doneCh <- true
	}()
	select {
	case <-doneCh:
		break
	case <-time.After(30 * time.Second):
		t.Fatal("outdated beacon time")
	}
}

func TestBeaconSync(t *testing.T) {
	n := 4
	thr := n/2 + 1
	period := 2 * time.Second

	genesisOffset := 2 * time.Second
	genesisTime := clock.NewFakeClock().Now().Add(genesisOffset).Unix()
	sch, beaconID := scheme.GetSchemeFromEnv(), test.GetBeaconIDFromEnv()

	bt := NewBeaconTest(t, n, thr, period, genesisTime, sch, beaconID)

	verifier := verifier2.NewVerifier(sch)

	var counter = &sync.WaitGroup{}
	myCallBack := func(i int) func(*chain.Beacon) {
		return func(b *chain.Beacon) {
			err := verifier.VerifyBeacon(*b, bt.dpublic)
			require.NoError(t, err)

			t.Logf("round %d done for %s\n", b.Round, bt.nodes[bt.searchNode(i)].private.Public.Address())
			counter.Done()
		}
	}

	doRound := func(count int, move time.Duration) {
		counter.Add(count)
		bt.MoveTime(t, move)
		checkWait(t, counter)
	}

	t.Log("serving beacons")
	for i := 0; i < n; i++ {
		bt.CallbackFor(i, myCallBack(i))
		bt.ServeBeacon(t, i)
	}

	t.Log("about to start beacons")
	bt.StartBeacons(t, n)
	t.Log("all beacons started")

	// move clock to genesis time
	t.Log("before genesis")
	now := bt.time.Now().Unix()
	toMove := genesisTime - now
	doRound(n, time.Duration(toMove)*time.Second)
	t.Log("after genesis")

	// do some rounds
	for i := 0; i < 2; i++ {
		t.Logf("round %d starting", i+2)
		doRound(n, period)
		t.Logf("round %d done", i+2)
	}

	t.Log("disable reception")
	// disable reception of all nodes but one
	online := 3
	bt.DisableReception(n - online)

	t.Log("doRounds AFTER disabling")
	// check that at least one node got the beacon
	doRound(online, period)
	t.Log("before enabling reception again")

	// enable reception again of all nodes
	bt.EnableReception(n - online)

	// we advance the clock, all "resuscitated nodes" will transmit a wrong
	// beacon, but they will see the beacon they send is late w.r.t. the round
	// they should be, so they will sync with the "safe online" nodes. They
	// will get the latest beacon and then directly run the right round
	// bt.MoveTime(period
	// n for the new round
	// n - online for the previous round that the others catch up
	t.Log("before doing round after enabling reception again")

	doRound(n+n-online, period)
}

func TestBeaconSimple(t *testing.T) {
	n := 3
	thr := n/2 + 1
	period := 2 * time.Second

	genesisTime := clock.NewFakeClock().Now().Unix() + 2
	sch, beaconID := scheme.GetSchemeFromEnv(), test.GetBeaconIDFromEnv()

	bt := NewBeaconTest(t, n, thr, period, genesisTime, sch, beaconID)

	verifier := verifier2.NewVerifier(sch)

	var counter = &sync.WaitGroup{}
	counter.Add(n)
	myCallBack := func(b *chain.Beacon) {
		// verify partial sig
		err := verifier.VerifyBeacon(*b, bt.dpublic)
		require.NoError(t, err)

		counter.Done()
	}

	for i := 0; i < n; i++ {
		bt.CallbackFor(i, myCallBack)
		// first serve all beacons
		bt.ServeBeacon(t, i)
	}

	bt.StartBeacons(t, n)
	// move clock before genesis time
	bt.MoveTime(t, 1*time.Second)
	for i := 0; i < n; i++ {
		bt.nodes[i].handler.Lock()

		started := bt.nodes[i].handler.started
		running := bt.nodes[i].handler.running
		serving := bt.nodes[i].handler.serving
		stopped := bt.nodes[i].handler.stopped

		bt.nodes[i].handler.Unlock()

		require.True(t, started, "handler %d has started?", i)
		require.True(t, running, "handler %d has run?", i)
		require.False(t, serving, "handler %d has served?", i)
		require.False(t, stopped, "handler %d has stopped?", i)
	}

	t.Log(" --------- moving to genesis ---------------")
	// move clock to genesis time
	bt.MoveTime(t, 1*time.Second)

	// check 1 period
	checkWait(t, counter)
	// check 2 period
	counter.Add(n)
	bt.MoveTime(t, period)
	checkWait(t, counter)
}

func TestBeaconThreshold(t *testing.T) {
	n := 3
	thr := n/2 + 1
	period := 2 * time.Second

	offsetGenesis := 2 * time.Second
	genesisTime := clock.NewFakeClock().Now().Add(offsetGenesis).Unix()
	sch, beaconID := scheme.GetSchemeFromEnv(), test.GetBeaconIDFromEnv()

	bt := NewBeaconTest(t, n, thr, period, genesisTime, sch, beaconID)

	verifier := verifier2.NewVerifier(sch)

	currentRound := uint64(0)
	var counter sync.WaitGroup
	myCallBack := func(i int) func(*chain.Beacon) {
		return func(b *chain.Beacon) {
			t.Logf(" - test: callback called for node %d - round %d\n", i, b.Round)
			// verify partial sig

			err := verifier.VerifyBeacon(*b, bt.dpublic)
			require.NoError(t, err)

			// callbacks are called for syncing up as well so we only decrease
			// waitgroup when it's the current round
			if b.Round == currentRound {
				counter.Done()
			}
		}
	}

	makeRounds := func(r int, howMany int) {
		func() {
			for i := 0; i < r; i++ {
				currentRound++
				counter.Add(howMany)
				bt.MoveTime(t, period)
				checkWait(t, &counter)
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	nRounds := 1
	// open connections for all but one
	for i := 0; i < n-1; i++ {
		bt.CallbackFor(i, myCallBack(i))
		bt.ServeBeacon(t, i)
	}

	// start all but one
	bt.StartBeacons(t, n-1)

	// move to genesis time and check they ran the round 1
	currentRound = 1
	counter.Add(n - 1)
	bt.MoveTime(t, offsetGenesis)
	checkWait(t, &counter)

	// make a few rounds
	makeRounds(nRounds, n-1)

	// launch the last one
	bt.ServeBeacon(t, n-1)
	bt.StartBeacon(t, n-1, true)
	t.Log("last node launched!")

	// 2s because of gRPC default timeouts backoff
	time.Sleep(2 * time.Second)
	bt.CallbackFor(n-1, myCallBack(n-1))
	t.Log("make new rounds!")

	// and then run a few rounds
	makeRounds(nRounds, n)

	t.Log("move time with all nodes")

	// expect lastnode to have catch up
	makeRounds(nRounds, n)
}

func TestProcessingPartialBeaconWithNonExistentIndexDoesntSegfault(t *testing.T) {
	sch := crypto.SchemeFromName(scheme.DefaultSchemeID)
	bt := NewBeaconTest(t, 3, 2, 30*time.Second, 0, sch, "default")

	packet := drand.PartialBeaconPacket{
		Round:       1,
		PreviousSig: []byte("deadbeef"),
		PartialSig:  []byte("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	}
	_, err := bt.nodes[0].handler.ProcessPartialBeacon(context.Background(), &packet)
	require.Error(t, err, "attempted to process beacon from node of index 25958, but it was not in the group file")
}

func TestSyncChainWithoutMetadata(t *testing.T) {
	logger := log.NewLogger(nil, log.LogDebug).Named("BeaconTest")
	expectedBeaconID := "someGreatBeacon"

	require.Equal(
		t,
		beaconIDToSync(logger, TestSyncRequest{round: 1, metadata: nil}, "127.0.0.1"),
		"default",
	)
	require.Equal(
		t,
		beaconIDToSync(logger, TestSyncRequest{round: 1, metadata: &pbCommon.Metadata{BeaconID: expectedBeaconID}}, "127.0.0.1"),
		expectedBeaconID,
	)
}

type TestSyncRequest struct {
	round    uint64
	metadata *pbCommon.Metadata
}

func (t TestSyncRequest) GetFromRound() uint64 {
	return t.round
}

func (t TestSyncRequest) GetMetadata() *pbCommon.Metadata {
	return t.metadata
}

func (b *BeaconTest) CallbackFor(i int, fn func(*chain.Beacon)) {
	j := b.searchNode(i)
	b.nodes[j].handler.AddCallback(b.nodes[j].private.Public.Address(), fn)
}
