package main

import "fmt"

// notifier is a interface that implements Notify method
type notifier interface {
	Notify()
}

// Message represents the message to be sent out
type Message struct {
	Address string
	ShopName string
	Contact Contact
}
type Contact struct {
	Name string
	Ph string
}

// send is the workhorse that sends notification out
// via a medium (slack/http/email/messagequeue etc)
func send(m *Message) error {
	fmt.Printf("sent notification to: \n%s\n", m)
	return nil
}

// Notify sends a notification
func (m *Message) Notify() {
	send(m)
}

// String is a Stringer for a Message
func (m *Message) String() string {
	return fmt.Sprintf(
		"==================================\n" +
		"Address: %s\n" +
		"Shop name: %s\n" +
		"Contact Name: %s\n" +
		"Contact Phone Number: %s\n"+
		"==================================",
		m.Address,
		m.ShopName,
		m.Contact.Name,
		m.Contact.Ph,
	)
}

// A real entrypoint for our program
func main() {
	m := &Message{
		Address:  "ba",
		ShopName: "sdf",
		Contact:  Contact{
			Name: "ab",
			Ph:   "123789899",
		},
	}
	m.Notify()
}