package users

// LoginRequest is the request body for the login endpoint
type LoginRequest struct {
	NameOrEmail string `json:"name_or_email"`
	Password    string `json:"password"`
}

// LoginResponse is the response body for the login endpoint
type LoginResponse struct {
	Token string `json:"token"`
}
