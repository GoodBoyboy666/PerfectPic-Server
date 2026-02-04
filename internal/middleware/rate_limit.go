package middleware

import (
	"fmt"
	"net/http"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/service"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	ips sync.Map
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		r: r,
		b: b,
	}

	go i.cleanupLoop()

	return i
}

func (i *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	if v, ok := i.ips.Load(ip); ok {
		if c, ok := v.(*client); ok {
			c.lastSeen = time.Now()
			return c.limiter
		}
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// Double check
	if v, ok := i.ips.Load(ip); ok {
		if c, ok := v.(*client); ok {
			c.lastSeen = time.Now()
			return c.limiter
		}
	}

	limiter := rate.NewLimiter(i.r, i.b)
	i.ips.Store(ip, &client{limiter: limiter, lastSeen: time.Now()})

	return limiter
}

func (i *IPRateLimiter) cleanupLoop() {
	for {
		time.Sleep(1 * time.Minute)
		i.ips.Range(func(key, value interface{}) bool {
			client, ok := value.(*client)
			if !ok {
				i.ips.Delete(key)
				return true
			}
			if time.Since(client.lastSeen) > 3*time.Minute {
				i.ips.Delete(key)
			}
			return true
		})
	}
}

// RateLimitMiddleware 创建一个动态限流中间件
func RateLimitMiddleware(rpsKey string, burstKey string) gin.HandlerFunc {
	// 内部建立一个 map 缓存 limiter，避免每次请求都创建 IPRateLimiter 对象
	// 这里其实是每个 group（auth/upload）共用一个 IPRateLimiter 实例
	var limiter *IPRateLimiter
	var once sync.Once

	return func(c *gin.Context) {
		// 检查总开关
		if !service.GetBool(consts.ConfigRateLimitEnabled) {
			c.Next()
			return
		}

		// 获取当前配置
		currentRPS := service.GetFloat64(rpsKey)
		currentBurst := service.GetInt(burstKey)

		// 初始化 Limiter
		once.Do(func() {
			limiter = NewIPRateLimiter(rate.Limit(currentRPS), currentBurst)
		})

		// 获取 IP 对应的 limiter
		ip := c.ClientIP()
		l := limiter.getLimiter(ip)

		// 动态更新 limit 和 burst (如果配置发生变更)
		if l.Limit() != rate.Limit(currentRPS) {
			l.SetLimit(rate.Limit(currentRPS))
		}
		if l.Burst() != currentBurst {
			l.SetBurst(currentBurst)
		}

		if !l.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁，请稍后再试"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// IntervalRateMiddleware 限制调用间隔的中间件
func IntervalRateMiddleware(interval time.Duration) gin.HandlerFunc {
	// 内部建立一个 map 缓存 IP 最后访问时间
	var requestTimes sync.Map

	// 启动清理协程
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			now := time.Now()
			requestTimes.Range(func(key, value interface{}) bool {
				if t, ok := value.(time.Time); ok {
					// 清理超过2倍间隔时间的记录
					if now.Sub(t) > interval*2 && now.Sub(t) > 5*time.Minute {
						requestTimes.Delete(key)
					}
				}
				return true
			})
		}
	}()

	return func(c *gin.Context) {
		// 检查是否开启敏感操作限流
		if !service.GetBool(consts.ConfigEnableSensitiveRateLimit) {
			c.Next()
			return
		}

		ip := c.ClientIP()

		val, ok := requestTimes.Load(ip)
		if ok {
			if t, ok := val.(time.Time); ok {
				if time.Since(t) < interval {
					c.JSON(http.StatusTooManyRequests, gin.H{"error": fmt.Sprintf("操作过于频繁，请等待 %v 后再试", interval)})
					c.Abort()
					return
				}
			}
		}

		requestTimes.Store(ip, time.Now())
		c.Next()
	}
}
