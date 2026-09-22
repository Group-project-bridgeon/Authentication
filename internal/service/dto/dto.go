package dto

type RegisterInput struct{ Email, Name, Password string }
type LoginInput struct{ Email, Password string }