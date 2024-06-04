package searcher

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
	"math/big"
	"time"
)

// API offers an API for accepting bundled transactions and MEV purposes
type API struct {
	b     ethapi.Backend
	chain *core.BlockChain
}

// NewSearcherAPI creates a new Tx Bundle API instance.
func NewSearcherAPI(b ethapi.Backend, chain *core.BlockChain) *API {
	return &API{
		b:     b,
		chain: chain,
	}
}

func (s *API) SearcherChainData(ctx context.Context, args ChainDataArgs) (*ChainDataResult, error) {
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}
	db, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if db == nil || err != nil {
		return nil, err
	}
	res := &ChainDataResult{
		Header:      parent,
		NextBaseFee: eip1559.CalcBaseFee(s.b.ChainConfig(), parent),
	}
	if len(args.Accounts) > 0 {
		res.Accounts = make(map[common.Address]*Account)
	}
	for account, keys := range args.Accounts {
		res.Accounts[account] = &Account{
			Balance: db.GetBalance(account).ToBig(),
			Nonce:   db.GetNonce(account),
		}
		if len(keys) > 0 {
			res.Accounts[account].State = make(map[common.Hash]common.Hash)
			for _, key := range keys {
				res.Accounts[account].State[key] = db.GetState(account, key)
			}
		}
	}
	return res, nil
}

func (s *API) SearcherCall(ctx context.Context, args CallArgs) (*CallResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("missing txs")
	}
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}

	timeoutMS := int64(5000)
	if args.Timeout != nil {
		timeoutMS = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMS)

	db, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if db == nil || err != nil {
		return nil, err
	}

	// override state
	if err = args.StateOverrides.Apply(db); err != nil {
		return nil, err
	}

	header := &types.Header{
		ParentHash:       parent.Hash(),
		Coinbase:         parent.Coinbase,
		Difficulty:       new(big.Int).Set(parent.Difficulty),
		Number:           new(big.Int).Set(parent.Number),
		GasLimit:         parent.GasLimit,
		Time:             parent.Time,
		MixDigest:        parent.MixDigest,
		ExcessBlobGas:    parent.ExcessBlobGas,
		ParentBeaconRoot: parent.ParentBeaconRoot,
	}
	if s.b.ChainConfig().IsLondon(parent.Number) {
		header.BaseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}
	blockCtx := core.NewEVMBlockContext(header, s.chain, &header.Coinbase)

	// Block overrides
	args.BlockOverrides.Apply(&blockCtx)

	// RPC Call gas cap
	globalGasCap := s.b.RPCGasCap()

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	// Setup context so it may be cancelled when the call
	// has completed or, in case of unmetered gas, setup
	// a context with a timeout
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// This makes sure resources are cleaned up
	defer cancel()

	// Feed each of the transactions into the VM ctx
	// And try and estimate the gas used
	ret := &CallResult{
		StateBlockNumber: parent.Number.Int64(),
		Txs:              make([]*TxResult, 0, len(args.Txs)),
	}
	for i, callMsg := range args.Txs {
		// Check if the context was cancelled (eg. timed-out)
		if err = ctx.Err(); err != nil {
			return nil, err
		}

		// Since it is a txCall we'll just prepare the
		// state with a random hash
		var txHash common.Hash
		rand.Read(txHash[:])

		// New random hash since its a call
		db.SetTxContext(txHash, i)

		// Convert tx args to msg to apply state transition
		var gasPtr *hexutil.Uint64
		if callMsg.Gas > 0 {
			gasPtr = (*hexutil.Uint64)(&callMsg.Gas)
		}
		txArgs := ethapi.TransactionArgs{
			From:                 &callMsg.From,
			To:                   callMsg.To,
			Gas:                  gasPtr,
			GasPrice:             (*hexutil.Big)(callMsg.GasPrice),
			MaxFeePerGas:         (*hexutil.Big)(callMsg.GasFeeCap),
			MaxPriorityFeePerGas: (*hexutil.Big)(callMsg.GasTipCap),
			Value:                (*hexutil.Big)(callMsg.Value),
			Nonce:                (*hexutil.Uint64)(callMsg.Nonce),
			Data:                 &callMsg.Data,
			AccessList:           &callMsg.AccessList,
		}
		msg, err := txArgs.ToMessage(globalGasCap, blockCtx.BaseFee)
		if err != nil {
			return nil, err
		}
		if callMsg.Nonce != nil {
			msg.Nonce = *callMsg.Nonce
			msg.SkipAccountChecks = false
		}

		// Create a new EVM environment
		vmConfig := vm.Config{
			NoBaseFee: !args.EnableBaseFee,
		}
		var tracer *Tracer
		if args.EnableTracer || args.EnableAccessList {
			cfg := TracerConfig{
				WithFrame:      args.EnableTracer,
				WithStorage:    args.EnableStorage,
				WithAccessList: args.EnableAccessList,
			}
			if cfg.WithAccessList {
				cfg.AccessListExcludes = make(map[common.Address]struct{})
				cfg.AccessListExcludes[msg.From] = struct{}{}
				if msg.To != nil {
					cfg.AccessListExcludes[*msg.To] = struct{}{}
				} else {
					cfg.AccessListExcludes[crypto.CreateAddress(msg.From, db.GetNonce(msg.From))] = struct{}{}
				}
				isPostMerge := blockCtx.Difficulty.Cmp(common.Big0) == 0
				for _, precompile := range vm.ActivePrecompiles(s.b.ChainConfig().Rules(blockCtx.BlockNumber, isPostMerge, blockCtx.Time)) {
					cfg.AccessListExcludes[precompile] = struct{}{}
				}
				cfg.AccessListExcludes[blockCtx.Coinbase] = struct{}{}
			}
			tracer = NewTracer(cfg)
			vmConfig.Tracer = tracer
		}
		evm := vm.NewEVM(blockCtx, core.NewEVMTxContext(msg), db, s.chain.Config(), vmConfig)

		// Apply state transition
		txResult := new(TxResult)
		result, err := core.ApplyMessage(evm, msg, gp)

		// Modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		db.Finalise(evm.ChainConfig().IsEIP158(blockCtx.BlockNumber))

		if err != nil {
			txResult.Error = fmt.Sprintf("%s (supplied gas %d)", err.Error(), msg.GasLimit)
		} else {
			txResult.Logs = db.GetLogs(txHash, blockCtx.BlockNumber.Uint64(), common.Hash{})
			if args.EnableTracer {
				txResult.Frame = tracer.Frame()
			}
			if args.EnableAccessList {
				txResult.AccessList = tracer.AccessList()
			}
			if result.Err != nil {
				txResult.Error = result.Err.Error()
			}
			reason, errUnpack := abi.UnpackRevert(result.Revert())
			if errUnpack == nil {
				txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
			}
			txResult.GasUsed = result.UsedGas
			txResult.ReturnData = result.ReturnData

			ret.TotalGasUsed += txResult.GasUsed
		}

		ret.Txs = append(ret.Txs, txResult)
	}

	return ret, nil
}

// SearcherCallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *API) SearcherCallBundle(ctx context.Context, args CallBundleArgs) (*CallBundleResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)

	var txs types.Transactions
	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	db, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if db == nil || err != nil {
		return nil, err
	}

	// override state
	if err := args.StateOverrides.Apply(db); err != nil {
		return nil, err
	}

	header := &types.Header{
		ParentHash:       parent.Hash(),
		Coinbase:         parent.Coinbase,
		Difficulty:       new(big.Int).Set(parent.Difficulty),
		Number:           new(big.Int).Set(parent.Number),
		GasLimit:         parent.GasLimit,
		Time:             parent.Time,
		MixDigest:        parent.MixDigest,
		ExcessBlobGas:    parent.ExcessBlobGas,
		ParentBeaconRoot: parent.ParentBeaconRoot,
	}
	if s.b.ChainConfig().IsLondon(parent.Number) {
		header.BaseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}
	blockCtx := core.NewEVMBlockContext(header, s.chain, &header.Coinbase)

	// block overrides
	args.BlockOverrides.Apply(&blockCtx)

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	bundleHash := sha3.NewLegacyKeccak256()
	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	ret := &CallBundleResult{
		CoinbaseDiff:      db.GetBalance(blockCtx.Coinbase).ToBig(),
		GasFees:           new(big.Int),
		EthSentToCoinbase: new(big.Int),
		StateBlockNumber:  parent.Number.Int64(),
		Txs:               make([]*BundleTxResult, 0, len(txs)),
	}
	for i, tx := range txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		db.SetTxContext(tx.Hash(), i)
		txResult, err := s.applyTransactionWithResult(gp, db, blockCtx, tx, args)
		if err != nil {
			return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
		}
		bundleHash.Write(tx.Hash().Bytes())
		ret.TotalGasUsed += txResult.GasUsed
		ret.GasFees.Add(ret.GasFees, txResult.GasFees)
		ret.Txs = append(ret.Txs, txResult)
	}

	ret.CoinbaseDiff = new(big.Int).Sub(db.GetBalance(blockCtx.Coinbase).ToBig(), ret.CoinbaseDiff)
	ret.EthSentToCoinbase = new(big.Int).Sub(ret.CoinbaseDiff, ret.GasFees)
	ret.BundleGasPrice = new(big.Int).Div(ret.CoinbaseDiff, big.NewInt(int64(ret.TotalGasUsed)))
	ret.BundleHash = common.BytesToHash(bundleHash.Sum(nil))

	return ret, nil
}

func (s *API) applyTransactionWithResult(gp *core.GasPool, db *state.StateDB, blockCtx vm.BlockContext, tx *types.Transaction, args CallBundleArgs) (*BundleTxResult, error) {
	chainConfig := s.b.ChainConfig()

	msg, err := core.TransactionToMessage(tx, types.MakeSigner(chainConfig, blockCtx.BlockNumber, blockCtx.Time), blockCtx.BaseFee)
	if err != nil {
		return nil, err
	}
	var tracer *Tracer
	vmConfig := *s.chain.GetVMConfig()
	if args.EnableTracer || args.EnableAccessList {
		cfg := TracerConfig{
			WithFrame:      args.EnableTracer,
			WithStorage:    args.EnableStorage,
			WithAccessList: args.EnableAccessList,
		}
		if cfg.WithAccessList {
			cfg.AccessListExcludes = make(map[common.Address]struct{})
			cfg.AccessListExcludes[msg.From] = struct{}{}
			if msg.To != nil {
				cfg.AccessListExcludes[*msg.To] = struct{}{}
			} else {
				cfg.AccessListExcludes[crypto.CreateAddress(msg.From, msg.Nonce)] = struct{}{}
			}
			isPostMerge := blockCtx.Difficulty.Cmp(common.Big0) == 0
			for _, precompile := range vm.ActivePrecompiles(chainConfig.Rules(blockCtx.BlockNumber, isPostMerge, blockCtx.Time)) {
				cfg.AccessListExcludes[precompile] = struct{}{}
			}
			cfg.AccessListExcludes[blockCtx.Coinbase] = struct{}{}
		}
		tracer = NewTracer(cfg)
		vmConfig.Tracer = tracer
	}
	// Create a new context to be used in the EVM environment
	evm := vm.NewEVM(blockCtx, core.NewEVMTxContext(msg), db, chainConfig, vmConfig)

	// Apply the transaction to the current state (included in the env).
	coinbaseBalanceBeforeTx := db.GetBalance(blockCtx.Coinbase)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Set the receipt logs and create the bloom filter.
	txResult := &BundleTxResult{
		TxHash:       tx.Hash(),
		GasUsed:      result.UsedGas,
		ReturnData:   result.ReturnData,
		Logs:         db.GetLogs(tx.Hash(), blockCtx.BlockNumber.Uint64(), common.Hash{}),
		CoinbaseDiff: new(big.Int).Sub(db.GetBalance(blockCtx.Coinbase).ToBig(), coinbaseBalanceBeforeTx.ToBig()),
		CallMsg: &CallMsg{
			From:       msg.From,
			To:         msg.To,
			Gas:        tx.Gas(),
			GasPrice:   tx.GasPrice(),
			GasFeeCap:  tx.GasFeeCap(),
			GasTipCap:  tx.GasTipCap(),
			Value:      tx.Value(),
			Nonce:      &msg.Nonce,
			Data:       tx.Data(),
			AccessList: tx.AccessList(),
		},
	}
	if args.EnableTracer {
		txResult.Frame = tracer.Frame()
	}
	if args.EnableAccessList {
		txResult.AccessList = tracer.AccessList()
	}
	txResult.GasPrice, err = tx.EffectiveGasTip(blockCtx.BaseFee)
	if err != nil {
		return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
	}
	txResult.GasFees = new(big.Int).Mul(big.NewInt(int64(result.UsedGas)), txResult.GasPrice)
	txResult.EthSentToCoinbase = new(big.Int).Sub(txResult.CoinbaseDiff, txResult.GasFees)
	txResult.GasPrice = new(big.Int).Div(txResult.CoinbaseDiff, big.NewInt(int64(result.UsedGas)))

	if result.Err != nil {
		txResult.Error = result.Err.Error()
	}
	reason, errUnpack := abi.UnpackRevert(result.Revert())
	if errUnpack == nil {
		txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
	}
	return txResult, err
}
