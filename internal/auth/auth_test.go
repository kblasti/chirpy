package auth

import (
    "testing"
    "time"

    "github.com/google/uuid"
)

func TestCorrect(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := time.Hour

	tknString, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	returnedID, err := ValidateJWT(tknString, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned error: %v", err)
	}

	if returnedID != userID {
        t.Fatalf("expected userID %v, got %v", userID, returnedID)
    }
}

func TestExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := -time.Minute

	tknString, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	returnedID, err := ValidateJWT(tknString, secret)
	if err == nil {
		t.Fatalf("ValidateJWT returned no error")
	}

	if returnedID != uuid.Nil {
		t.Fatalf("ValidateJWT returned a non-nil uuid: %v", returnedID)
	}
}

func TestWrongSecret(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := time.Hour

	tknString, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	returnedID, err := ValidateJWT(tknString, "incorrect")
	if err == nil {
		t.Fatalf("ValidateJWT returned no error")
	}

	if returnedID != uuid.Nil {
		t.Fatalf("ValidateJWT returned a non-nil uuid: %v", returnedID)
	}
}