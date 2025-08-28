/*
* @desc:登录
* @company:云南奇讯科技有限公司
* @Author: yixiaohu
* @Date:   2022/4/27 21:51
 */

package system

import (
	"github.com/gogf/gf/v2/frame/g"
	commonApi "github.com/tiger1103/gfast/v3/api/v1/common"
	"github.com/tiger1103/gfast/v3/internal/app/system/model"
)

type UserLoginReq struct {
	g.Meta     `path:"/login" tags:"系统后台/登录" method:"post" summary:"用户登录"`
	Username   string `p:"username" v:"required#用户名不能为空"`
	Password   string `p:"password" v:"required#密码不能为空"`
	VerifyCode string `p:"verifyCode"`
	VerifyKey  string `p:"verifyKey"`
}

type UserLoginRes struct {
	g.Meta      `mime:"application/json"`
	UserInfo    *model.LoginUserRes `json:"userInfo"`
	Token       string              `json:"token"`
	MenuList    []*model.UserMenus  `json:"menuList"`
	Permissions []string            `json:"permissions"`
}

type UserLoginReq2 struct {
	g.Meta   `path:"/login2" tags:"系统后台/登录" method:"post" summary:"用户登录"`
	UserName string `p:"user_name" v:"required#用户名不能为空"`
	Password string `p:"password" v:"required#密码不能为空"`
}

type UserLoginRes2 struct {
	g.Meta   `mime:"application/json"`
	UserInfo *model.LoginUserRes `json:"userInfo"`
	Token    string              `json:"token"`
}

type UserLoginOutReq struct {
	g.Meta `path:"/logout" tags:"系统后台/登录" method:"get" summary:"退出登录"`
	commonApi.Author
}

type UserLoginOutRes struct {
}

type TokenInstrospectReq struct {
	g.Meta `path:"/token/introspect" tags:"系统后台/登录" method:"post" summary:"Token验证"`
	commonApi.Author
}

type TokenInstrospectRes struct {
	g.Meta   `mime:"application/json"`
	UserID   int64  `json:"user_id"`
	UserName string `json:"user_name"`
}
