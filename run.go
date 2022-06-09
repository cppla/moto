package main

import (
	"moto/config"
	"moto/controller"
	"moto/utils"
	"sync"
)

func main()  {
	defer utils.Logger.Sync()

	utils.Logger.Info("MOTO start...")
	wg := &sync.WaitGroup{}
	for _, v := range config.GlobalCfg.Rules {
		wg.Add(1)
		go controller.Listen(v, wg)
	}
	wg.Wait()
	utils.Logger.Info("MOTO close...")
}
