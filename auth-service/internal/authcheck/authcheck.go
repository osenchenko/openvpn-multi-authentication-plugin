package authcheck

import (
	"auth-service/internal/globals"
	"sort"
	"sync"
	"time"
)

type ConfigProvider interface {
	NumAuthServers() int
	AuthCheckUser() string
	AuthCheckPass() string
	AuthCheckInterval() int
	AppLogger() globals.AppLogger
	AuthServerName(i int) string
	SetAvailableServers(arr []int)
	SetUnavailableServers(arr []int)
}

// //TODO: configProvider, radius client interface, сделать через интерфейсы
// // чтобы можно было не зависеть от реализации: LDAP или Radius
func StartAuthCheckTask(cfg ConfigProvider, client globals.AuthClientProvider) {
	logger := cfg.AppLogger()
	num := cfg.NumAuthServers()
	availableServers := make([]int, num)
	unavailableServers := make([]int, num)
	user := cfg.AuthCheckUser()
	pass := cfg.AuthCheckPass()
	interval := time.Duration(cfg.AuthCheckInterval()) * time.Second
	var m, m2 sync.Mutex
	var wg sync.WaitGroup
	for {
		availableServers = availableServers[:0]
		unavailableServers = unavailableServers[:0]
		logger.Debug("Start monitoring authentication check")
		for i := 0; i < num; i++ {
			wg.Add(1)
			go func(i2 int) {
				defer wg.Done()
				r, err := client.CheckAuthenticateUser(user, pass, i2)
				if err != nil {
					logger.Errorf("Server %s is unavailable. Error %s", cfg.AuthServerName(i2), err)
					m2.Lock()
					defer m2.Unlock()
					unavailableServers = append(unavailableServers, i2)
					return
				}
				if !r {
					logger.Errorf("Unable authenticate monitoring user. Server %s is unavailable", cfg.AuthServerName(i2))
					m2.Lock()
					defer m2.Unlock()
					unavailableServers = append(unavailableServers, i2)
					return
				}
				m.Lock()
				availableServers = append(availableServers, i2)
				m.Unlock()

			}(i)
		}
		wg.Wait()
		sort.Ints(availableServers)
		sort.Ints(unavailableServers)
		cfg.SetAvailableServers(availableServers)
		logger.Debug("Available servers: %#v", availableServers)
		cfg.SetUnavailableServers(unavailableServers)
		logger.Debug("Unavailable servers: %#v", unavailableServers)
		logger.Debug("End monitoring authentication check")
		time.Sleep(interval)
	}

}
