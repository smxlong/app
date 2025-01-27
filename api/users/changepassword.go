package users

// ChangePasswordRequest is the request body for the change password endpoint
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ChangePasswordResponse is the response body for the change password endpoint
type ChangePasswordResponse struct {
	MessageResponse `json:",inline"`
}
