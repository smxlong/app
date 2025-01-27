package users

// SignupRequest is the request body for the signup endpoint
type SignupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest is the request body for the login endpoint
type LoginRequest struct {
	NameOrEmail string `json:"name_or_email"`
	Password    string `json:"password"`
}

// ChangePasswordRequest is the request body for the change password endpoint
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// RequestResetPasswordRequest is the request body for the request reset password endpoint
type RequestResetPasswordRequest struct {
	Email string `json:"email"`
}

// ResetPasswordRequest is the request body for the reset password endpoint
type ResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// DeleteRequest is the request body for the delete endpoint
type DeleteRequest struct {
	Password string `json:"password"`
}
