package users

// RequestResetPasswordRequest is the request body for the request reset password endpoint
type RequestResetPasswordRequest struct {
	Email string `json:"email"`
}

// RequestResetPasswordResponse is the response body for the request reset password endpoint
type RequestResetPasswordResponse struct {
	MessageResponse `json:",inline"`
}

// ResetPasswordRequest is the request body for the reset password endpoint
type ResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// ResetPasswordResponse is the response body for the reset password endpoint
type ResetPasswordResponse struct {
	MessageResponse `json:",inline"`
}
