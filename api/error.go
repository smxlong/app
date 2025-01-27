package api

import (
	"fmt"
	"net/http"
)

// StatusCodeError is an error with a status code
type StatusCodeError struct {
	StatusCode int
}

// Error returns the error message
func (e *StatusCodeError) Error() string {
	return fmt.Sprintf("%d %s", e.StatusCode, http.StatusText(e.StatusCode))
}

// Code returns the status code
func (e *StatusCodeError) Code() int {
	return e.StatusCode
}

// WithMessage returns an error with a message
func (e *StatusCodeError) WithMessage(message string) *Error {
	return &Error{e, message}
}

// Error is an error with a status code and a message
type Error struct {
	*StatusCodeError
	Message string
}

// Error returns the error message
func (e *Error) Error() string {
	return fmt.Sprintf("%d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Message)
}

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.StatusCodeError
}

var (
	// ErrBadRequest returns a 400 error
	ErrBadRequest = &StatusCodeError{http.StatusBadRequest}
	// ErrUnauthorized returns a 401 error
	ErrUnauthorized = &StatusCodeError{http.StatusUnauthorized}
	// ErrPaymentRequired returns a 402 error
	ErrPaymentRequired = &StatusCodeError{http.StatusPaymentRequired}
	// ErrForbidden returns a 403 error
	ErrForbidden = &StatusCodeError{http.StatusForbidden}
	// ErrNotFound returns a 404 error
	ErrNotFound = &StatusCodeError{http.StatusNotFound}
	// ErrMethodNotAllowed returns a 405 error
	ErrMethodNotAllowed = &StatusCodeError{http.StatusMethodNotAllowed}
	// ErrNotAcceptable returns a 406 error
	ErrNotAcceptable = &StatusCodeError{http.StatusNotAcceptable}
	// ErrProxyAuthRequired returns a 407 error
	ErrProxyAuthRequired = &StatusCodeError{http.StatusProxyAuthRequired}
	// ErrRequestTimeout returns a 408 error
	ErrRequestTimeout = &StatusCodeError{http.StatusRequestTimeout}
	// ErrConflict returns a 409 error
	ErrConflict = &StatusCodeError{http.StatusConflict}
	// ErrGone returns a 410 error
	ErrGone = &StatusCodeError{http.StatusGone}
	// ErrLengthRequired returns a 411 error
	ErrLengthRequired = &StatusCodeError{http.StatusLengthRequired}
	// ErrPreconditionFailed returns a 412 error
	ErrPreconditionFailed = &StatusCodeError{http.StatusPreconditionFailed}
	// ErrRequestEntityTooLarge returns a 413 error
	ErrRequestEntityTooLarge = &StatusCodeError{http.StatusRequestEntityTooLarge}
	// ErrRequestURITooLong returns a 414 error
	ErrRequestURITooLong = &StatusCodeError{http.StatusRequestURITooLong}
	// ErrUnsupportedMediaType returns a 415 error
	ErrUnsupportedMediaType = &StatusCodeError{http.StatusUnsupportedMediaType}
	// ErrRequestedRangeNotSatisfiable returns a 416 error
	ErrRequestedRangeNotSatisfiable = &StatusCodeError{http.StatusRequestedRangeNotSatisfiable}
	// ErrExpectationFailed returns a 417 error
	ErrExpectationFailed = &StatusCodeError{http.StatusExpectationFailed}
	// ErrTeapot returns a 418 error
	ErrTeapot = &StatusCodeError{http.StatusTeapot}
	// ErrInternalServerError returns a 500 error
	ErrInternalServerError = &StatusCodeError{http.StatusInternalServerError}
	// ErrNotImplemented returns a 501 error
	ErrNotImplemented = &StatusCodeError{http.StatusNotImplemented}
	// ErrBadGateway returns a 502 error
	ErrBadGateway = &StatusCodeError{http.StatusBadGateway}
	// ErrServiceUnavailable returns a 503 error
	ErrServiceUnavailable = &StatusCodeError{http.StatusServiceUnavailable}
	// ErrGatewayTimeout returns a 504 error
	ErrGatewayTimeout = &StatusCodeError{http.StatusGatewayTimeout}
)

// coder is implemented by errors that have a status code
type coder interface {
	Code() int
}

// ErrorCode returns the code of any error, returning 500 if the error is not a
// StatusCodeError
func ErrorCode(err error) int {
	if e, ok := err.(coder); ok {
		return e.Code()
	}
	return http.StatusInternalServerError
}
