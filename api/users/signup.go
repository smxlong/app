package users

// SignupRequest is the request body for the signup endpoint
type SignupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignupResponse is the response body for the signup endpoint
type SignupResponse struct {
	MessageResponse `json:",inline"`
}
