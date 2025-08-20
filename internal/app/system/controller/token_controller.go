package controller

import (
	"context"

	"github.com/tiger1103/gfast/v3/api/v1/system"
	"github.com/tiger1103/gfast/v3/internal/app/system/service"
)

var (
	TokenController = tokenController{}
)

type tokenController struct {
	BaseController
}

func (t *tokenController) Introspect(ctx context.Context, req *system.TokenInstrospectReq) (res *system.TokenInstrospectRes, err error) {
	v1 := service.Context().GetLoginUser(ctx)

	res = &system.TokenInstrospectRes{
		UserID:   int64(v1.Id),
		UserName: v1.UserName,
	}

	return
}
