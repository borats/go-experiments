package main

import "fmt"

// FakeNotifier is a fake notifier interface for mock testing
type FakeNotifier interface {
	NotifyFake()
}

// NotifyFake represents a mocked out Notify() so we
// testing *everything* except the methods that relies
// on contracts outside the bounded context of this
// subsystem (e.g., network).
func (m *Message) NotifyFake() {
	fmt.Printf("sent fake notification to \n%+v\nwithout calling send()", m)
}