package controller

import (
	"context"

	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/tiger1103/gfast/v3/api/v1/system"
	"github.com/tiger1103/gfast/v3/internal/app/system/model"
	"github.com/tiger1103/gfast/v3/internal/app/system/service"
	"github.com/tiger1103/gfast/v3/library/libUtils"
)

var (
	OutController = &outController{}
)

type outController struct {
	BaseController
}

func (c *userController) Register(ctx context.Context, req *system.UserRegisterReq) (res *system.UserRegisterRes, err error) {
	id, err := service.SysUser().Register(ctx, req)
	if err != nil {
		return
	}
	res = &system.UserRegisterRes{
		ID: id,
	}
	return
}

func (c *outController) Login2(ctx context.Context, req *system.UserLoginReq2) (res *system.UserLoginRes2, err error) {
	var (
		userInfo *model.LoginUserRes
		token    string
	)

	ip := libUtils.GetClientIp(ctx)
	userAgent := libUtils.GetUserAgent(ctx)
	in := &system.UserLoginReq{
		Username: req.UserName,
		Password: req.Password,
	}
	userInfo, err = service.SysUser().GetAdminUserByUsernamePassword(ctx, in)
	if err != nil {
		// 保存登录失败的日志信息
		service.SysLoginLog().Invoke(gctx.New(), &model.LoginLogParams{
			Status:    0,
			Username:  req.UserName,
			Ip:        ip,
			UserAgent: userAgent,
			Msg:       err.Error(),
			Module:    "系统后台",
		})
		return
	}
	err = service.SysUser().UpdateLoginInfo(ctx, userInfo.Id, ip)
	if err != nil {
		return
	}
	// 报存登录成功的日志信息
	service.SysLoginLog().Invoke(gctx.New(), &model.LoginLogParams{
		Status:    1,
		Username:  req.UserName,
		Ip:        ip,
		UserAgent: userAgent,
		Msg:       "登录成功",
		Module:    "系统后台",
	})
	key := gconv.String(userInfo.Id) + "-" + gmd5.MustEncryptString(userInfo.UserName) + gmd5.MustEncryptString(userInfo.UserPassword)
	if g.Cfg().MustGet(ctx, "gfToken.multiLogin").Bool() {
		key = gconv.String(userInfo.Id) + "-" + gmd5.MustEncryptString(userInfo.UserName) + gmd5.MustEncryptString(userInfo.UserPassword+ip+userAgent)
	}
	token, err = service.GfToken().GenerateToken(ctx, key, userInfo)
	if err != nil {
		g.Log().Error(ctx, err)
		err = gerror.New("登录失败，后端服务出现错误")
		return
	}

	res = &system.UserLoginRes2{
		UserInfo: userInfo,
		Token:    token,
	}
	//用户在线状态保存
	service.SysUserOnline().Invoke(gctx.New(), &model.SysUserOnlineParams{
		UserAgent: userAgent,
		Uuid:      gmd5.MustEncrypt(token),
		Token:     token,
		Username:  userInfo.UserName,
		Ip:        ip,
	})
	return
}
