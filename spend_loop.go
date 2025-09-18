package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hoosat-Oy/HTND/app/appmessage"
	"github.com/Hoosat-Oy/HTND/domain/consensus/model/externalapi"
	"github.com/Hoosat-Oy/HTND/domain/consensus/utils/consensushashing"
	"github.com/Hoosat-Oy/HTND/domain/consensus/utils/constants"
	"github.com/Hoosat-Oy/HTND/domain/consensus/utils/subnetworks"
	"github.com/Hoosat-Oy/HTND/domain/consensus/utils/transactionid"
	"github.com/Hoosat-Oy/HTND/domain/consensus/utils/txscript"
	utxopkg "github.com/Hoosat-Oy/HTND/domain/consensus/utils/utxo"
	"github.com/Hoosat-Oy/HTND/infrastructure/network/rpcclient"
	"github.com/Hoosat-Oy/HTND/util"
	"github.com/kaspanet/go-secp256k1"
	"github.com/pkg/errors"
)

var (
	pendingOutpoints      = make(map[appmessage.RPCOutpoint]time.Time)
	pendingOutpointsMutex sync.Mutex
)

func spendLoop(client *rpcclient.RPCClient, addresses *addressesList,
	utxosChangedNotificationChan <-chan *appmessage.UTXOsChangedNotificationMessage) <-chan struct{} {

	doneChan := make(chan struct{})

	spawn("spendLoop", func() {
		log.Infof("Fetching the initial UTXO set")
		utxos, err := fetchSpendableUTXOs(client, addresses.myAddress.EncodeAddress())
		if err != nil {
			panic(err)
		}
		log.Infof("Initial UTXO count %d\n", len(utxos))

		cfg := activeConfig()
		ticker := time.NewTicker(time.Duration(cfg.TransactionInterval/2) * time.Millisecond) // Reduced for frequent checks
		for range ticker.C {
			healthChan := make(chan struct{})
			go func() {
				timer := time.NewTimer(1 * time.Minute)
				defer timer.Stop()
				select {
				case <-healthChan:
				case <-timer.C:
					log.Criticalf("HEALTCHECK FAILED")
					fmt.Println("HEALTCHECK FAILED")
					os.Exit(1)
				}
			}()
			hasFunds, err := maybeSendTransaction(client, addresses, utxos)
			if err != nil {
				panic(err)
			}

			checkTransactions(utxosChangedNotificationChan)

			if !hasFunds {
				log.Infof("No spendable UTXOs. Refetching UTXO set.")
				for {
					var err error
					utxos, err = fetchSpendableUTXOs(client, addresses.myAddress.EncodeAddress())
					if err == nil {
						log.Infof("New Spendable UTXO count %d", len(utxos))
						break
					}
					log.Warnf("Failed to fetch UTXOs: %v. Retrying in 2s...", err)
					time.Sleep(2 * time.Second)
				}
			}

			if atomic.LoadInt32(&shutdown) != 0 {
				close(doneChan)
				return
			}

			close(healthChan)
		}
	})

	return doneChan
}

func checkTransactions(utxosChangedNotificationChan <-chan *appmessage.UTXOsChangedNotificationMessage) {
	isDone := false
	for !isDone {
		select {
		case notification := <-utxosChangedNotificationChan:
			pendingOutpointsMutex.Lock()
			for _, removed := range notification.Removed {
				sendTime, ok := pendingOutpoints[*removed.Outpoint]
				if ok {
					log.Infof("Output %s:%d accepted. Time since send: %s",
						removed.Outpoint.TransactionID, removed.Outpoint.Index, time.Since(sendTime))
					delete(pendingOutpoints, *removed.Outpoint)
				}
			}
			pendingOutpointsMutex.Unlock()
		default:
			isDone = true
		}
	}

	pendingOutpointsMutex.Lock()
	defer pendingOutpointsMutex.Unlock()
	for pendingOutpoint, txTime := range pendingOutpoints {
		timeSince := time.Since(txTime)
		if timeSince > 10*time.Minute {
			log.Tracef("Outpoint %s:%d is pending for %s",
				pendingOutpoint.TransactionID, pendingOutpoint.Index, timeSince)
		}
	}
}

const balanceEpsilon = 10_000        // 10,000 sompi = 0.0001 Hoosat
const feeAmount = balanceEpsilon * 5 // Reduced fee for efficiency
const maxTxsPerTick = 100            // Number of transactions to send per tick

var stats struct {
	sync.Mutex
	numTxs uint64
	since  time.Time
}

func maybeSendTransaction(client *rpcclient.RPCClient, addresses *addressesList,
	availableUTXOs map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry) (hasFunds bool, err error) {

	selectedUTXOs, err := selectUTXOs(availableUTXOs)
	if err != nil {
		return false, err
	}

	if len(selectedUTXOs) == 0 {
		return false, nil
	}

	// Limit to maxTxsPerTick
	if len(selectedUTXOs) > maxTxsPerTick {
		selectedUTXOs = selectedUTXOs[:maxTxsPerTick]
	}

	hasFunds = true
	txsSent := 0

	for i, utxo := range selectedUTXOs {
		selectedValue := utxo.UTXOEntry.Amount
		if selectedValue < 2*balanceEpsilon+feeAmount {
			log.Infof("UTXO %s:%d has %d sompi, too small to split", utxo.Outpoint.TransactionID, utxo.Outpoint.Index, selectedValue)
			continue
		}

		// Split into two equal outputs minus fee
		totalSendAmount := selectedValue - feeAmount
		sendAmount := totalSendAmount / 2
		change := totalSendAmount - sendAmount

		// Ensure minimum amounts
		if sendAmount < balanceEpsilon || change < balanceEpsilon {
			log.Infof("Cannot split UTXO %s:%d (%d sompi) into two outputs >= %d sompi", utxo.Outpoint.TransactionID, utxo.Outpoint.Index, selectedValue, balanceEpsilon)
			continue
		}

		// Both outputs to myAddress for splitting
		rpcTransaction, err := generateTransaction(
			addresses.myPrivateKey, []*appmessage.UTXOsByAddressesEntry{utxo}, sendAmount, change, addresses.myAddress, addresses.myAddress)
		if err != nil {
			log.Warnf("Error generating transaction for UTXO %s:%d: %v", utxo.Outpoint.TransactionID, utxo.Outpoint.Index, err)
			continue
		}

		if rpcTransaction.Outputs[0].Amount == 0 || rpcTransaction.Outputs[1].Amount == 0 {
			log.Warnf("Got transaction with 0 value output for UTXO %s:%d", utxo.Outpoint.TransactionID, utxo.Outpoint.Index)
			continue
		}

		setPending(availableUTXOs, []*appmessage.UTXOsByAddressesEntry{utxo})
		spawn(fmt.Sprintf("sendTransaction-%d", i), func() {
			transactionID, err := sendTransaction(client, rpcTransaction)
			if err != nil {
				errMessage := err.Error()
				if !strings.Contains(errMessage, "orphan transaction") &&
					!strings.Contains(errMessage, "is already in the mempool") &&
					!strings.Contains(errMessage, "is an orphan") &&
					!strings.Contains(errMessage, "already spent by transaction") {
					log.Errorf("Error sending transaction for UTXO %s:%d: %v", utxo.Outpoint.TransactionID, utxo.Outpoint.Index, err)
				}
				unsetPending(availableUTXOs, []*appmessage.UTXOsByAddressesEntry{utxo})
			} else {
				log.Infof("Sent transaction %s worth %f hoosat with 1 input and 2 outputs (UTXO %s:%d)", transactionID,
					float64(totalSendAmount)/constants.SompiPerHoosat, utxo.Outpoint.TransactionID, utxo.Outpoint.Index)
				unsetPending(availableUTXOs, []*appmessage.UTXOsByAddressesEntry{utxo})
				func() {
					stats.Lock()
					defer stats.Unlock()
					stats.numTxs++
					timePast := time.Since(stats.since)
					if timePast > 10*time.Second {
						log.Infof("Tx rate: %f/sec", float64(stats.numTxs)/timePast.Seconds())
						stats.numTxs = 0
						stats.since = time.Now()
					}
				}()
			}
		})
		txsSent++
	}

	log.Infof("Sent %d transactions in this tick", txsSent)
	return hasFunds, nil
}

func fetchSpendableUTXOs(client *rpcclient.RPCClient, address string) (map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, error) {
	pendingOutpointsMutex.Lock()
	for k := range pendingOutpoints {
		delete(pendingOutpoints, k)
	}
	log.Infof("Cleared the pending Outpoints")
	pendingOutpointsMutex.Unlock()
	getUTXOsByAddressesResponse, err := client.GetUTXOsByAddresses([]string{address})
	if err != nil {
		return nil, err
	}
	dagInfo, err := client.GetBlockDAGInfo()
	if err != nil {
		return nil, err
	}
	log.Infof("Checking if UTXO is spendable")
	spendableUTXOs := make(map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, 0)
	for _, entry := range getUTXOsByAddressesResponse.Entries {
		if !isUTXOSpendable(entry, dagInfo.VirtualDAAScore) {
			continue
		}
		spendableUTXOs[*entry.Outpoint] = entry.UTXOEntry
	}
	return spendableUTXOs, nil
}

func isUTXOSpendable(entry *appmessage.UTXOsByAddressesEntry, virtualSelectedParentBlueScore uint64) bool {
	blockDAAScore := entry.UTXOEntry.BlockDAAScore
	if !entry.UTXOEntry.IsCoinbase {
		const minConfirmations = 10
		return blockDAAScore+minConfirmations < virtualSelectedParentBlueScore
	}
	coinbaseMaturity := activeConfig().ActiveNetParams.BlockCoinbaseMaturity
	return blockDAAScore+coinbaseMaturity < virtualSelectedParentBlueScore
}

func setPending(availableUTXOs map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry,
	selectedUTXOs []*appmessage.UTXOsByAddressesEntry) {
	pendingOutpointsMutex.Lock()
	defer pendingOutpointsMutex.Unlock()
	for _, utxo := range selectedUTXOs {
		pendingOutpoints[*utxo.Outpoint] = time.Now()
	}
}

func unsetPending(availableUTXOs map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry,
	selectedUTXOs []*appmessage.UTXOsByAddressesEntry) {
	pendingOutpointsMutex.Lock()
	defer pendingOutpointsMutex.Unlock()
	for _, utxo := range selectedUTXOs {
		delete(pendingOutpoints, *utxo.Outpoint)
	}
}

func filterSpentUTXOsAndCalculateBalance(utxos []*appmessage.UTXOsByAddressesEntry) (
	filteredUTXOs []*appmessage.UTXOsByAddressesEntry, balance uint64) {
	balance = 0
	for _, utxo := range utxos {
		if _, ok := pendingOutpoints[*utxo.Outpoint]; ok {
			continue
		}
		balance += utxo.UTXOEntry.Amount
		filteredUTXOs = append(filteredUTXOs, utxo)
	}
	return filteredUTXOs, balance
}

func randomizeSpendAddress(addresses *addressesList) util.Address {
	spendAddressIndex := rand.Intn(len(addresses.spendAddresses))
	return addresses.spendAddresses[spendAddressIndex]
}

func randomizeSpendAmount() uint64 {
	const maxAmountToSent = 10 * feeAmount
	amountToSend := rand.Int63n(int64(maxAmountToSent))
	amountToSend = amountToSend / balanceEpsilon * balanceEpsilon
	if amountToSend < balanceEpsilon {
		amountToSend = balanceEpsilon
	}
	return uint64(amountToSend)
}

func selectUTXOs(
	utxos map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry,
) (
	selectedUTXOs []*appmessage.UTXOsByAddressesEntry,
	err error,
) {
	// Collect all non-pending UTXOs
	type utxoPair struct {
		outpoint appmessage.RPCOutpoint
		entry    *appmessage.RPCUTXOEntry
	}
	utxoList := make([]utxoPair, 0, len(utxos))
	pendingOutpointsMutex.Lock()
	for outpoint, entry := range utxos {
		if _, isPending := pendingOutpoints[outpoint]; isPending {
			continue
		}
		if entry.Amount >= 2*balanceEpsilon+feeAmount {
			utxoList = append(utxoList, utxoPair{outpoint, entry})
		}
	}
	pendingOutpointsMutex.Unlock()

	if len(utxoList) == 0 {
		return nil, nil
	}

	// Sort by amount descending (largest first)
	sort.Slice(utxoList, func(i, j int) bool {
		return utxoList[i].entry.Amount > utxoList[j].entry.Amount
	})

	// Select up to maxTxsPerTick UTXOs
	n := len(utxoList)
	if n > maxTxsPerTick {
		n = maxTxsPerTick
	}
	selectedUTXOs = make([]*appmessage.UTXOsByAddressesEntry, 0, n)
	for i := 0; i < n; i++ {
		selectedUTXOs = append(selectedUTXOs, &appmessage.UTXOsByAddressesEntry{
			Outpoint:  &utxoList[i].outpoint,
			UTXOEntry: utxoList[i].entry,
		})
	}

	return selectedUTXOs, nil
}

func generateTransaction(keyPair *secp256k1.SchnorrKeyPair, selectedUTXOs []*appmessage.UTXOsByAddressesEntry,
	sompisToSend uint64, change uint64, toAddress util.Address,
	fromAddress util.Address) (*appmessage.RPCTransaction, error) {
	inputs := make([]*externalapi.DomainTransactionInput, len(selectedUTXOs))
	for i, utxo := range selectedUTXOs {
		outpointTransactionIDBytes, err := hex.DecodeString(utxo.Outpoint.TransactionID)
		if err != nil {
			return nil, err
		}
		outpointTransactionID, err := transactionid.FromBytes(outpointTransactionIDBytes)
		if err != nil {
			return nil, err
		}
		outpoint := externalapi.DomainOutpoint{
			TransactionID: *outpointTransactionID,
			Index:         utxo.Outpoint.Index,
		}
		utxoScriptPublicKeyScript, err := hex.DecodeString(utxo.UTXOEntry.ScriptPublicKey.Script)
		if err != nil {
			return nil, err
		}

		inputs[i] = &externalapi.DomainTransactionInput{
			PreviousOutpoint: outpoint,
			SigOpCount:       1,
			UTXOEntry: utxopkg.NewUTXOEntry(
				utxo.UTXOEntry.Amount,
				&externalapi.ScriptPublicKey{
					Script:  utxoScriptPublicKeyScript,
					Version: utxo.UTXOEntry.ScriptPublicKey.Version,
				},
				utxo.UTXOEntry.IsCoinbase,
				utxo.UTXOEntry.BlockDAAScore,
			),
		}
	}

	fromScript, err := txscript.PayToAddrScript(fromAddress)
	if err != nil {
		return nil, err
	}
	// Two outputs to myAddress for splitting
	mainOutput := &externalapi.DomainTransactionOutput{
		Value:           sompisToSend,
		ScriptPublicKey: fromScript,
	}
	changeOutput := &externalapi.DomainTransactionOutput{
		Value:           change,
		ScriptPublicKey: fromScript,
	}
	outputs := []*externalapi.DomainTransactionOutput{mainOutput, changeOutput}

	domainTransaction := &externalapi.DomainTransaction{
		Version:      constants.MaxTransactionVersion,
		Inputs:       inputs,
		Outputs:      outputs,
		LockTime:     0,
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Gas:          0,
		Payload:      nil,
	}

	for i, input := range domainTransaction.Inputs {
		signatureScript, err := txscript.SignatureScript(domainTransaction, i, consensushashing.SigHashAll, keyPair,
			&consensushashing.SighashReusedValues{})
		if err != nil {
			return nil, err
		}
		input.SignatureScript = signatureScript
	}

	rpcTransaction := appmessage.DomainTransactionToRPCTransaction(domainTransaction)
	return rpcTransaction, nil
}

func sendTransaction(client *rpcclient.RPCClient, rpcTransaction *appmessage.RPCTransaction) (string, error) {
	tx, err := appmessage.RPCTransactionToDomainTransaction(rpcTransaction)
	if err != nil {
		return "", errors.Wrapf(err, "error submitting transaction")
	}
	submitTransactionResponse, err := client.SubmitTransaction(rpcTransaction, consensushashing.TransactionID(tx).String(), false)
	if err != nil {
		return "", errors.Wrapf(err, "error submitting transaction")
	}
	return submitTransactionResponse.TransactionID, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
