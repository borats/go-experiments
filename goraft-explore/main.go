package main

import (
	"flag"
	"strings"

	"github.com/coreos/etcd/raft/raftpb"
)

var (
	cluster = flag.String("cluster", "http://127.0.0.1:9021", "comma separated cluster peers")
	id      = flag.Int("id", 1, "node ID")
	kvport  = flag.Int("port", 9121, "key-value server port")
	join    = flag.Bool("join", false, "join an existing cluster")
)

func init() {
	flag.Parse()
}

func main() {
	proposeCh := make(chan string)
	defer close(proposeCh)

	confChangeCh := make(chan raftpb.ConfChange)
	defer close(confChangeCh)

	// raft provides a commit stream for the proposals from the http api
	var kvs *kvstore
	getSnapshot := func() ([]byte, error) {
		return kvs.getSnapshot()
	}

	commitCh, errorCh, snapshotterReady := newRaftNode(
		*id,
		strings.Split(*cluster, ","),
		*join,
		getSnapshot,
		proposeCh,
		confChangeCh)

	kvs = newKVStore(<-snapshotterReady, proposeCh, commitCh, errorCh)

	// the key-value http handler will propose updates to raft
	serveHttpKVAPI(kvs, *kvport, confChangeCh, errorCh)
}
