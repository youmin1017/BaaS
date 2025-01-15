package outputs

type CreateUserOutput struct {
	Body struct {
		UserID string `json:"user_id" example:"123e4567-e89b-12d3-a456-426614174000" doc:"User ID"`
	}
}
