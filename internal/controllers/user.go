package controllers

import (
	"baas-auth/internal/configs"
	"baas-auth/internal/controllers/inputs"
	"baas-auth/internal/controllers/outputs"
	"baas-auth/internal/services"
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

type UserController struct {
	config  *configs.Config
	service *services.Service
}

func InitUserController(config *configs.Config, service *services.Service) *UserController {
	controller := &UserController{}
	controller.config = config
	controller.service = service

	return controller
}

func (uc *UserController) RegisterCreateUser(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-user",
		Method:      http.MethodPost,
		Path:        "/user",
		Summary:     "Create a user",
		Description: "Create a new user.",
		Tags:        []string{"User"},
	}, func(ctx context.Context, input *inputs.CreateUserInput) (*outputs.CreateUserOutput, error) {
		user_id, err := uuid.Parse(input.Body.UserID)

		if err != nil {
			return nil, err
		}

		err = uc.service.CreateUserWithUUID(user_id, input.Body.Email)

		if err != nil {
			return nil, err
		}

		resp := &outputs.CreateUserOutput{}
		resp.Body.UserID = user_id.String()

		return resp, nil
	})
}
