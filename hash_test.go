package main

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(h))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Errorf("cost = %d, want %d", cost, bcrypt.DefaultCost)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("hunter2")); err != nil {
		t.Errorf("the hash does not match the password: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("wrong")); err == nil {
		t.Error("a wrong password was accepted")
	}
}
