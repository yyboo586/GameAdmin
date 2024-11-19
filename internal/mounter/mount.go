/*
* @desc:组件挂载器
* @company:云南奇讯科技有限公司
* @Author: yixiaohu<yxh669@qq.com>
* @Date:   2024/10/25 08:36
 */

package mounter

import (
	"context"
	"github.com/gogf/gf/v2/net/ghttp"
	"sync"
)

type MountHandler func(ctx context.Context, s *ghttp.Server)

var (
	funcOptions = make([]MountHandler, 0)
	fLock       sync.Mutex
)

func Mount(handler MountHandler) {
	fLock.Lock()
	defer fLock.Unlock()
	funcOptions = append(funcOptions, handler)
}

func DoMount(ctx context.Context, s *ghttp.Server) {
	for _, fn := range funcOptions {
		fn(ctx, s)
	}
}
