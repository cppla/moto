package main

import (
	"flag"
	"fmt"
	"moto/config"
	"moto/controller"
	"moto/utils"
	"os"
	"sync"
)

func printHelp() {
	fmt.Println("MOTO - Weak Network Accelerator & Smart Proxy")
	fmt.Println("Usage: moto [--help]")
	fmt.Println("Options:")
	fmt.Println("  --help            Show this help and exit")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println("  Reads config from config/setting.json by default.")
	fmt.Println("  Accelerator modes:")
	fmt.Println("    - role=client: runs 4 proxy modes and uses persistent tunnels to server.")
	fmt.Println("    - role=server: accepts tunnels and dials real targets.")
	fmt.Println()
	fmt.Println("Loss adaptation:")
	fmt.Println("  Dynamically chooses duplication (1..5x) based on observed loss between client and server.")
	fmt.Println("  Default mapping:")
	fmt.Println("    <1%  -> 1x; <10% -> 2x; <20% -> 3x; <30% -> 4x; >=30% -> 5x")
}

func main() {
	help := flag.Bool("help", false, "Show help")
	flag.Parse()
	if *help {
		printHelp()
		os.Exit(0)
	}

	defer utils.Logger.Sync()

	utils.Logger.Info("MOTO start...")
	// init accelerator (client/server role) if enabled
	controller.InitAccelerator()
	wg := &sync.WaitGroup{}
	for _, v := range config.GlobalCfg.Rules {
		wg.Add(1)
		go controller.Listen(v, wg)
	}
	wg.Wait()
	utils.Logger.Info("MOTO close...")
}
