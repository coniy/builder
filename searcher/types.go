package searcher

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
	"math/big"
)

type OverrideAccount struct {
	Nonce     *uint64                     `json:"nonce,omitempty"`
	Code      *hexutil.Bytes              `json:"code,omitempty"`
	Balance   *big.Int                    `json:"balance,omitempty"`
	State     map[common.Hash]common.Hash `json:"state,omitempty"`
	StateDiff map[common.Hash]common.Hash `json:"stateDiff,omitempty"`
}

type StateOverrides map[common.Address]*OverrideAccount

// Apply overrides the fields of specified accounts into the given state.
func (diff StateOverrides) Apply(state *state.StateDB) error {
	if diff == nil {
		return nil
	}
	for addr, account := range diff {
		// Override account nonce.
		if account.Nonce != nil {
			state.SetNonce(addr, *account.Nonce)
		}
		// Override account(contract) code.
		if account.Code != nil {
			state.SetCode(addr, *account.Code)
		}
		// Override account balance.
		if account.Balance != nil {
			state.SetBalance(addr, uint256.MustFromBig(account.Balance))
		}
		if account.State != nil && account.StateDiff != nil {
			return fmt.Errorf("account %s has both 'state' and 'stateDiff'", addr.Hex())
		}
		// Replace entire state if caller requires.
		if account.State != nil {
			state.SetStorage(addr, account.State)
		}
		// Apply state diff into specified accounts.
		if account.StateDiff != nil {
			for key, value := range account.StateDiff {
				state.SetState(addr, key, value)
			}
		}
	}
	// Now finalize the changes. Finalize is normally performed between transactions.
	// By using finalize, the overrides are semantically behaving as
	// if they were created in a transaction just before the tracing occur.
	state.Finalise(false)
	return nil
}

type BlockOverrides struct {
	Number      *big.Int        `json:"number,omitempty"`
	NumberShift int64           `json:"numberShift,omitempty"`
	Difficulty  *big.Int        `json:"difficulty,omitempty"`
	Time        *uint64         `json:"time,omitempty"`
	TimeShift   int64           `json:"timeShift,omitempty"`
	GasLimit    *uint64         `json:"gasLimit,omitempty"`
	Coinbase    *common.Address `json:"coinbase,omitempty"`
	Random      *common.Hash    `json:"random,omitempty"`
	BaseFee     *big.Int        `json:"baseFee,omitempty"`
	BlobBaseFee *big.Int        `json:"blobBaseFee,omitempty"`
}

// Apply overrides the given header fields into the given block context.
func (diff *BlockOverrides) Apply(blockCtx *vm.BlockContext) {
	if diff == nil {
		return
	}
	if diff.Number != nil {
		blockCtx.BlockNumber = diff.Number
	}
	if diff.NumberShift != 0 {
		blockCtx.BlockNumber = new(big.Int).Add(blockCtx.BlockNumber, big.NewInt(diff.NumberShift))
	}
	if diff.Difficulty != nil {
		blockCtx.Difficulty = diff.Difficulty
	}
	if diff.Time != nil {
		blockCtx.Time = *diff.Time
	}
	if diff.TimeShift != 0 {
		blockCtx.Time += uint64(diff.TimeShift)
	}
	if diff.GasLimit != nil {
		blockCtx.GasLimit = *diff.GasLimit
	}
	if diff.Coinbase != nil {
		blockCtx.Coinbase = *diff.Coinbase
	}
	if diff.Random != nil {
		blockCtx.Random = diff.Random
	}
	if diff.BaseFee != nil {
		blockCtx.BaseFee = diff.BaseFee
	}
	if diff.BlobBaseFee != nil {
		blockCtx.BlobBaseFee = diff.BlobBaseFee
	}
}

type CallMsg struct {
	From      common.Address  `json:"from,omitempty"`
	To        *common.Address `json:"to,omitempty"`
	Gas       uint64          `json:"gas,omitempty"`
	GasPrice  *big.Int        `json:"gasPrice,omitempty"`
	GasFeeCap *big.Int        `json:"gasFeeCap,omitempty"`
	GasTipCap *big.Int        `json:"gasTipCap,omitempty"`
	Value     *big.Int        `json:"value,omitempty"`
	Nonce     *uint64         `json:"nonce,omitempty"`
	Data      hexutil.Bytes   `json:"data,omitempty"`

	// Introduced by AccessListTxType transaction.
	AccessList types.AccessList `json:"accessList,omitempty"`
}

type CallArgs struct {
	Txs                    []*CallMsg            `json:"txs,omitempty"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber,omitempty"`
	Timeout                *int64                `json:"timeout,omitempty"`
	EnableBaseFee          bool                  `json:"enableBaseFee,omitempty"`
	EnableTracer           bool                  `json:"enableTracer,omitempty"`
	EnableAccessList       bool                  `json:"enableAccessList,omitempty"`
	EnableStorage          bool                  `json:"enableStorage,omitempty"`
	BlockOverrides         *BlockOverrides       `json:"blockOverrides,omitempty"`
	StateOverrides         StateOverrides        `json:"stateOverrides,omitempty"`
}

type CallResult struct {
	StateBlockNumber int64       `json:"stateBlockNumber,omitempty"`
	TotalGasUsed     uint64      `json:"totalGasUsed,omitempty"`
	Txs              []*TxResult `json:"txs,omitempty"`
}

type TxResult struct {
	GasUsed    uint64           `json:"gasUsed,omitempty"`
	Error      string           `json:"error,omitempty"`
	ReturnData hexutil.Bytes    `json:"returnData,omitempty"`
	Frame      *Frame           `json:"frame,omitempty"`
	Logs       []*types.Log     `json:"logs,omitempty"`
	AccessList types.AccessList `json:"accessList,omitempty"`
}

type CallBundleArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs,omitempty"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber,omitempty"`
	Timeout                *int64                `json:"timeout,omitempty"`
	EnableTracer           bool                  `json:"enableTracer,omitempty"`
	EnableAccessList       bool                  `json:"enableAccessList,omitempty"`
	EnableStorage          bool                  `json:"enableStorage,omitempty"`
	BlockOverrides         *BlockOverrides       `json:"blockOverrides,omitempty"`
	StateOverrides         StateOverrides        `json:"stateOverrides,omitempty"`
}

type CallBundleResult struct {
	BundleGasPrice    *big.Int          `json:"bundleGasPrice,omitempty"`
	BundleHash        common.Hash       `json:"bundleHash,omitempty"`
	CoinbaseDiff      *big.Int          `json:"coinbaseDiff,omitempty"`
	GasFees           *big.Int          `json:"gasFees,omitempty"`
	EthSentToCoinbase *big.Int          `json:"ethSentToCoinbase,omitempty"`
	StateBlockNumber  int64             `json:"stateBlockNumber,omitempty"`
	TotalGasUsed      uint64            `json:"totalGasUsed,omitempty"`
	Txs               []*BundleTxResult `json:"txs,omitempty"`
}

type BundleTxResult struct {
	TxHash            common.Hash      `json:"txHash,omitempty"`
	GasUsed           uint64           `json:"gasUsed,omitempty"`
	Error             string           `json:"error,omitempty"`
	ReturnData        hexutil.Bytes    `json:"returnData,omitempty"`
	CoinbaseDiff      *big.Int         `json:"coinbaseDiff,omitempty"`
	GasFees           *big.Int         `json:"gasFees,omitempty"`
	EthSentToCoinbase *big.Int         `json:"ethSentToCoinbase,omitempty"`
	GasPrice          *big.Int         `json:"gasPrice,omitempty"`
	CallMsg           *CallMsg         `json:"callMsg,omitempty"`
	Frame             *Frame           `json:"frame,omitempty"`
	Logs              []*types.Log     `json:"logs,omitempty"`
	AccessList        types.AccessList `json:"accessList,omitempty"`
}

type Frame struct {
	Opcode vm.OpCode `json:"opcode,omitempty"`
	Data   any       `json:"data,omitempty"`
	Subs   []*Frame  `json:"subs,omitempty"`

	Parent *Frame `json:"-"`
}

func (f *Frame) UnmarshalJSON(data []byte) error {
	type Alias struct {
		Opcode vm.OpCode       `json:"opcode,omitempty"`
		Data   json.RawMessage `json:"data,omitempty"`
		Subs   []*Frame        `json:"subs,omitempty"`
	}
	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	f.Opcode = alias.Opcode
	f.Subs = alias.Subs
	switch f.Opcode {
	case vm.CALL, vm.STATICCALL, vm.DELEGATECALL, vm.CREATE, vm.CREATE2, vm.SELFDESTRUCT:
		call := new(FrameCall)
		if err := json.Unmarshal(alias.Data, call); err != nil {
			return err
		}
		f.Data = call
	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		log := new(FrameLog)
		if err := json.Unmarshal(alias.Data, log); err != nil {
			return err
		}
		f.Data = log
	case vm.SLOAD, vm.SSTORE, vm.TLOAD, vm.TSTORE:
		storage := new(FrameStorage)
		if err := json.Unmarshal(alias.Data, storage); err != nil {
			return err
		}
		f.Data = storage
	default:
		return fmt.Errorf("unsupported opcode %v", f.Opcode.String())
	}
	return nil
}

type FrameCall struct {
	From         common.Address `json:"from,omitempty"`
	To           common.Address `json:"to,omitempty"`
	Value        *big.Int       `json:"value,omitempty"`
	Gas          uint64         `json:"gas,omitempty"`
	GasUsed      uint64         `json:"gasUsed,omitempty"`
	Error        string         `json:"error,omitempty"`
	RevertReason string         `json:"revertReason,omitempty"`
	Input        hexutil.Bytes  `json:"input,omitempty"`
	Output       hexutil.Bytes  `json:"output,omitempty"`
}

func (f *Frame) Logs() []*types.Log {
	if f == nil {
		return nil
	}
	var logs []*types.Log
	for _, sub := range f.Subs {
		if l, ok := sub.Data.(*FrameLog); ok && l != nil {
			logs = append(logs, l.ToLog())
		}
	}
	return logs
}

type FrameLog struct {
	Address common.Address `json:"address,omitempty"`
	Topics  []common.Hash  `json:"topics,omitempty"`
	Data    hexutil.Bytes  `json:"data,omitempty"`
}

func (l *FrameLog) ToLog() *types.Log {
	if l == nil {
		return nil
	}
	return &types.Log{
		Address: l.Address,
		Topics:  l.Topics,
		Data:    l.Data,
	}
}

type FrameStorage struct {
	Key   common.Hash `json:"key,omitempty"`
	Value common.Hash `json:"value,omitempty"`
}

type ChainDataArgs struct {
	StateBlockNumberOrHash rpc.BlockNumberOrHash            `json:"stateBlockNumber,omitempty"`
	Accounts               map[common.Address][]common.Hash `json:"accounts,omitempty"`
}

type ChainDataResult struct {
	Header      *types.Header               `json:"header,omitempty"`
	NextBaseFee *big.Int                    `json:"nextBaseFee,omitempty"`
	Accounts    map[common.Address]*Account `json:"accounts,omitempty"`
}

type Account struct {
	Nonce   uint64                      `json:"nonce,omitempty"`
	Balance *big.Int                    `json:"balance,omitempty"`
	State   map[common.Hash]common.Hash `json:"state,omitempty"`
}
