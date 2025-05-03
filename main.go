package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/Hoosat-Oy/HTND/app/appmessage"
	"github.com/Hoosat-Oy/HTND/infrastructure/network/rpcclient"
	"github.com/Hoosat-Oy/HTND/util/profiling"

	"github.com/Hoosat-Oy/HTND/infrastructure/os/signal"
	"github.com/Hoosat-Oy/HTND/util/panics"
)

var shutdown int32 = 0

func main() {
	interrupt := signal.InterruptListener()
	err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing config: %+v", err)
		os.Exit(1)
	}
	defer backendLog.Close()

	defer panics.HandlePanic(log, "main", nil)

	if cfg.Profile != "" {
		profiling.Start(cfg.Profile, log)
	}

	addresses, err := loadAddresses()
	if err != nil {
		panic(err)
	}

	rpcAddress, err := activeConfig().ActiveNetParams.NormalizeRPCServerAddress(activeConfig().RPCServer)
	if err != nil {
		panic(err)
	}

	client, err := rpcclient.NewRPCClient(rpcAddress)
	if err != nil {
		panic(err)
	}

	client.SetTimeout(5 * time.Minute)

	utxosChangedNotificationChan := make(chan *appmessage.UTXOsChangedNotificationMessage, 100)
	err = client.RegisterForUTXOsChangedNotifications([]string{addresses.myAddress.EncodeAddress()},
		func(notification *appmessage.UTXOsChangedNotificationMessage) {
			utxosChangedNotificationChan <- notification
		})
	if err != nil {
		panic(err)
	}

	spendLoopDoneChan := spendLoop(client, addresses, utxosChangedNotificationChan)

	<-interrupt

	atomic.AddInt32(&shutdown, 1)

	<-spendLoopDoneChan
}
