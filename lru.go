package main

import (
	"fmt"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
)

type SessionNode struct {
	prv, nxt *SessionNode
	item     quic.Session
}

func EmptyNode() *SessionNode {
	return &SessionNode{}
}

func InitNode(session quic.Session) *SessionNode {
	return &SessionNode{nil, nil, session}
}

type LinkedList struct {
	sz         int
	head, tail *SessionNode
}

func InitLinkedList() LinkedList {
	ll := LinkedList{0, EmptyNode(), EmptyNode()}
	ll.head.nxt = ll.tail
	ll.tail.prv = ll.head
	return ll
}

func (ll *LinkedList) AddNode(session quic.Session) *SessionNode {
	ll.sz++
	node := InitNode(session)
	ll.AddNodeFirst(node)
	return node
}

func (ll *LinkedList) AddNodeFirst(node *SessionNode) *SessionNode {
	node.nxt = ll.head.nxt
	node.prv = ll.head
	ll.head.nxt.prv = node
	ll.head.nxt = node
	return node
}

func (ll *LinkedList) RemoveNode(node *SessionNode) {
	ll.sz--
	prv := node.prv
	nxt := node.nxt
	prv.nxt = nxt
	nxt.prv = prv
	node.nxt = nil
	node.prv = nil
}

func (ll *LinkedList) RemoveLast() {
	node := ll.tail.prv
	node.item.CloseWithError(0, "done")
	ll.RemoveNode(node)
}

func (ll *LinkedList) MoveUp(node *SessionNode) {
	ll.RemoveNode(node)
	ll.AddNodeFirst(node)
}

type LRUCache struct {
	items    map[string]*SessionNode
	ll       LinkedList
	capacity int
	mu       sync.Mutex
}

func InitLRUCache(capacity int) *LRUCache {
	cache := LRUCache{make(map[string]*SessionNode), InitLinkedList(), capacity, sync.Mutex{}}
	return &cache
}

func (cache *LRUCache) Add(ip string, session quic.Session) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	node, ok := cache.items[ip]

	if !ok {
		node = cache.ll.AddNode(session)
		cache.items[ip] = node
		if cache.ll.sz > cache.capacity {
			cache.ll.RemoveLast()
		}
		return
	}

	node.item = session
	cache.ll.MoveUp(node)
}

func (cache *LRUCache) Get(ip string) (quic.Session, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	node, ok := cache.items[ip]

	if !ok {
		return nil, fmt.Errorf("not found")
	}

	cache.ll.MoveUp(node)
	return node.item, nil
}
