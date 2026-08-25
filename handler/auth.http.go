package handler

import (
	"golang-fiber-jwt-auth/errs"
	"golang-fiber-jwt-auth/service"
	"golang-fiber-jwt-auth/token"

	"github.com/gofiber/fiber/v2"
)

type authHandler struct {
	authSvc service.AuthService
}

func NewAuthHandler(authSvc service.AuthService) authHandler {
	return authHandler{authSvc: authSvc}
}

func (h authHandler) Register(c *fiber.Ctx) error {
	var req service.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return handleError(c, errs.NewValidationError("invalid request body"))
	}

	resp, err := h.authSvc.Register(c.Context(), req)
	if err != nil {
		return handleError(c, err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h authHandler) Login(c *fiber.Ctx) error {
	var req service.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return handleError(c, errs.NewValidationError("invalid request body"))
	}

	resp, err := h.authSvc.Login(c.Context(), req)
	if err != nil {
		return handleError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h authHandler) Refresh(c *fiber.Ctx) error {
	var req service.RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return handleError(c, errs.NewValidationError("invalid request body"))
	}

	resp, err := h.authSvc.Refresh(c.Context(), req)
	if err != nil {
		return handleError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h authHandler) Logout(c *fiber.Ctx) error {
	var req service.LogoutRequest
	if err := c.BodyParser(&req); err != nil {
		return handleError(c, errs.NewValidationError("invalid request body"))
	}

	if err := h.authSvc.Logout(c.Context(), req); err != nil {
		return handleError(c, err)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

type meResponse struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

func (h authHandler) Me(c *fiber.Ctx) error {
	claims, ok := c.Locals(claimsLocalsKey).(token.Claims)
	if !ok {
		return handleError(c, errs.NewUnauthorizedError("missing auth context"))
	}

	return c.Status(fiber.StatusOK).JSON(meResponse{ID: claims.Sub, Role: claims.Role})
}
