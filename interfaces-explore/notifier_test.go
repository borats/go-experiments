package main

import "testing"

func TestNotify(t *testing.T) {
	tests := []struct {
		name   string
		member Message
	}{
		{
			name: "test-valid",
			member: Message{
				Address:  "24 Sverak Rd, Helsinki, Finland",
				ShopName: "Borats Famous Coffee House",
				Contact: Contact{
					Name: "Borats Nolan",
					Ph:   "12345678",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Message{
				Address:  tt.member.Address,
				ShopName: tt.member.ShopName,
				Contact:  tt.member.Contact,
			}
			m.NotifyFake()
		})
	}
}