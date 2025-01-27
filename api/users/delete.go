package users

// DeleteRequest is the request body for the delete endpoint
type DeleteRequest struct {
	Password string `json:"password"`
}

// DeleteResponse is the response body for the delete endpoint
type DeleteResponse struct {
	MessageResponse `json:",inline"`
}
