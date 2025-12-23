//go:build wasip1

package main

import "fmt"

// Error codes for external consumption
// Internal details are logged but not exposed in error messages
const (
	ErrCodeInvalidInput      = "INVALID_INPUT"
	ErrCodeValidationFailed  = "VALIDATION_FAILED"
	ErrCodePriceFetchFailed  = "PRICE_FETCH_FAILED"
	ErrCodePriceInvalid      = "PRICE_INVALID"
	ErrCodeThresholdInvalid  = "THRESHOLD_INVALID"
	ErrCodeContractFailed    = "CONTRACT_CREATION_FAILED"
	ErrCodeSigningFailed     = "SIGNING_FAILED"
	ErrCodeRelayFailed       = "RELAY_OPERATION_FAILED"
	ErrCodeQuoteNotFound     = "QUOTE_NOT_FOUND"
	ErrCodeQuoteExpired      = "QUOTE_EXPIRED"
	ErrCodeSecretFetchFailed = "SECRET_FETCH_FAILED"
	ErrCodeInternalError     = "INTERNAL_ERROR"
)

// SanitizedError wraps an internal error with a safe external message
type SanitizedError struct {
	Code     string // Error code for programmatic handling
	Message  string // Safe message for external consumption
	internal error  // Internal error for logging (not exposed)
}

func (e *SanitizedError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the internal error for logging
func (e *SanitizedError) Unwrap() error {
	return e.internal
}

// Error constructors - these create safe error messages without internal details

func ErrInvalidInput(detail string) error {
	return &SanitizedError{
		Code:    ErrCodeInvalidInput,
		Message: detail,
	}
}

func ErrValidationFailed(field string) error {
	return &SanitizedError{
		Code:    ErrCodeValidationFailed,
		Message: fmt.Sprintf("validation failed for field: %s", field),
	}
}

func ErrPriceFetchFailed(internal error) error {
	return &SanitizedError{
		Code:     ErrCodePriceFetchFailed,
		Message:  "failed to fetch current price",
		internal: internal,
	}
}

func ErrPriceInvalid(internal error) error {
	return &SanitizedError{
		Code:     ErrCodePriceInvalid,
		Message:  "price data is invalid or out of bounds",
		internal: internal,
	}
}

func ErrThresholdTooClose() error {
	return &SanitizedError{
		Code:    ErrCodeThresholdInvalid,
		Message: fmt.Sprintf("threshold must be at least %.0f%% away from current price", MinThresholdDistance*100),
	}
}

func ErrThresholdInvalid(reason string) error {
	return &SanitizedError{
		Code:    ErrCodeThresholdInvalid,
		Message: reason,
	}
}

func ErrContractCreationFailed(internal error) error {
	return &SanitizedError{
		Code:     ErrCodeContractFailed,
		Message:  "failed to create price contract",
		internal: internal,
	}
}

func ErrSigningFailed(internal error) error {
	return &SanitizedError{
		Code:     ErrCodeSigningFailed,
		Message:  "cryptographic signing failed",
		internal: internal,
	}
}

func ErrRelayPublishFailed(internal error) error {
	return &SanitizedError{
		Code:     ErrCodeRelayFailed,
		Message:  "failed to publish to relay",
		internal: internal,
	}
}

func ErrRelayFetchFailed(internal error) error {
	return &SanitizedError{
		Code:     ErrCodeRelayFailed,
		Message:  "failed to fetch from relay",
		internal: internal,
	}
}

func ErrQuoteNotFound() error {
	return &SanitizedError{
		Code:    ErrCodeQuoteNotFound,
		Message: "quote not found",
	}
}

func ErrQuoteExpired() error {
	return &SanitizedError{
		Code:    ErrCodeQuoteExpired,
		Message: "quote has expired and cannot be evaluated",
	}
}

func ErrSecretFetchFailed(secretName string, internal error) error {
	return &SanitizedError{
		Code:     ErrCodeSecretFetchFailed,
		Message:  fmt.Sprintf("failed to fetch required secret: %s", secretName),
		internal: internal,
	}
}

func ErrInternal(internal error) error {
	return &SanitizedError{
		Code:     ErrCodeInternalError,
		Message:  "internal error occurred",
		internal: internal,
	}
}
