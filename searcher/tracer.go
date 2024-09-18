package searcher

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"math/big"
	"sync/atomic"
)

// accessList is an accumulator for the set of accounts and storage slots an EVM
// contract execution touches.
type accessList map[common.Address]accessListSlots

// accessListSlots is an accumulator for the set of storage slots within a single
// contract that an EVM contract execution touches.
type accessListSlots map[common.Hash]struct{}

// newAccessList creates a new accessList.
func newAccessList() accessList {
	return make(map[common.Address]accessListSlots)
}

// addAddress adds an address to the accesslist.
func (al accessList) addAddress(address common.Address) {
	// Set address if not previously present
	if _, present := al[address]; !present {
		al[address] = make(map[common.Hash]struct{})
	}
}

// addSlot adds a storage slot to the accesslist.
func (al accessList) addSlot(address common.Address, slot common.Hash) {
	// Set address if not previously present
	al.addAddress(address)

	// Set the slot on the surely existent storage set
	al[address][slot] = struct{}{}
}

// accesslist converts the accesslist to a types.AccessList.
func (al accessList) accessList() types.AccessList {
	acl := make(types.AccessList, 0, len(al))
	for addr, slots := range al {
		tuple := types.AccessTuple{Address: addr, StorageKeys: []common.Hash{}}
		for slot := range slots {
			tuple.StorageKeys = append(tuple.StorageKeys, slot)
		}
		acl = append(acl, tuple)
	}
	return acl
}

var _ tracers.Tracer = (*Tracer)(nil)

type Tracer struct {
	config       TracerConfig
	env          *vm.EVM
	rootFrame    *Frame
	currentFrame *Frame
	gasLimit     uint64
	usedGas      uint64
	interrupt    atomic.Bool // Atomic flag to signal execution interruption
	reason       error       // Textual reason for the interruption
	list         accessList  // Set of accounts and storage slots touched
}

type TracerConfig struct {
	WithFrame          bool                        `json:"withFrame,omitempty"`
	WithStorage        bool                        `json:"withStorage,omitempty"`
	WithAccessList     bool                        `json:"withAccessList,omitempty"`
	AccessListExcludes map[common.Address]struct{} `json:"accessListExcludes,omitempty"`
}

// NewTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func NewTracer(config TracerConfig) *Tracer {
	// First call frame contains tx context info
	// and is populated on start and end.
	tracer := &Tracer{
		config: config,
	}
	if config.WithAccessList {
		tracer.list = newAccessList()
	}
	return tracer
}

func (t *Tracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

func (t *Tracer) CaptureTxEnd(restGas uint64) {
	t.usedGas = t.gasLimit - restGas
	if t.config.WithFrame {
		call, ok := t.rootFrame.Data.(*FrameCall)
		if ok && call != nil {
			call.GasUsed = t.usedGas
		}
	}
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *Tracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env
	if t.config.WithFrame {
		if value != nil && value.Sign() == 0 {
			value = nil
		}
		t.rootFrame = &Frame{
			Opcode: vm.CALL,
			Data: &FrameCall{
				From:  from,
				To:    to,
				Value: value,
				Gas:   t.gasLimit,
				Input: common.CopyBytes(input),
			},
		}
		if create {
			t.rootFrame.Opcode = vm.CREATE
		}
		t.currentFrame = t.rootFrame
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *Tracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	if t.config.WithFrame {
		t.rootFrame.processOutput(gasUsed, output, err)
		t.currentFrame = nil
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *Tracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	if t.config.WithFrame {
		sub := &Frame{
			Opcode: typ,
			Data: &FrameCall{
				From:  from,
				To:    to,
				Value: value,
				Gas:   gas,
				Input: common.CopyBytes(input),
			},
			Parent: t.currentFrame,
		}
		t.currentFrame.Subs = append(t.currentFrame.Subs, sub)
		t.currentFrame = sub
	}
}

func (f *Frame) processOutput(gasUsed uint64, output []byte, err error) {
	call := f.Data.(*FrameCall)
	call.GasUsed = gasUsed
	output = common.CopyBytes(output)
	call.Output = output
	if err == nil {
		return
	}
	call.Error = err.Error()
	if !errors.Is(err, vm.ErrExecutionReverted) || len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		call.RevertReason = unpacked
	}
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *Tracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if t.config.WithFrame {
		if t.currentFrame == nil {
			return
		}
		t.currentFrame.processOutput(gasUsed, output, err)
		t.currentFrame = t.currentFrame.Parent
	}
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *Tracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// Skip if tracing was interrupted
	if t.interrupt.Load() || err != nil {
		return
	}

	stack := scope.Stack.Data()
	stackLen := len(stack)
	switch op {
	case vm.SLOAD:
		if stackLen < 1 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := t.env.StateDB.GetState(scope.Contract.Address(), slot)
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Data:   &FramePair{(*hexutil.Big)(slot.Big()), (*hexutil.Big)(value.Big())},
			})
		}
		if t.config.WithAccessList {
			addr := scope.Contract.Address()
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				slot := common.Hash(stack[stackLen-1].Bytes32())
				t.list.addSlot(addr, slot)
			}
		}
	case vm.SSTORE:
		if stackLen < 2 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := common.Hash(stack[stackLen-2].Bytes32())
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Data:   &FramePair{(*hexutil.Big)(slot.Big()), (*hexutil.Big)(value.Big())},
			})
		}
		if t.config.WithAccessList {
			addr := scope.Contract.Address()
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				slot := common.Hash(stack[stackLen-1].Bytes32())
				t.list.addSlot(addr, slot)
			}
		}
	case vm.TLOAD:
		if stackLen < 1 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := t.env.StateDB.(vm.StateDB).GetTransientState(scope.Contract.Address(), slot)
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Data:   &FramePair{(*hexutil.Big)(slot.Big()), (*hexutil.Big)(value.Big())},
			})
		}
	case vm.TSTORE:
		if stackLen < 2 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := common.Hash(stack[stackLen-2].Bytes32())
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Data:   &FramePair{(*hexutil.Big)(slot.Big()), (*hexutil.Big)(value.Big())},
			})
		}
	case vm.BALANCE, vm.EXTCODESIZE, vm.EXTCODECOPY, vm.EXTCODEHASH, vm.SELFDESTRUCT:
		if stackLen < 1 {
			return
		}
		if t.config.WithStorage {
			key := stack[stackLen-1]
			addr := common.Address(key.Bytes20())
			switch op {
			case vm.BALANCE:
				t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
					Opcode: op,
					Data:   &FramePair{(*hexutil.Big)(key.ToBig()), (*hexutil.Big)(t.env.StateDB.GetBalance(addr).ToBig())},
				})
			case vm.EXTCODESIZE:
				size := len(t.env.StateDB.GetCode(addr))
				t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
					Opcode: op,
					Data:   &FramePair{(*hexutil.Big)(key.ToBig()), (*hexutil.Big)(big.NewInt(int64(size)))},
				})
			case vm.EXTCODEHASH:
				hash := crypto.Keccak256Hash(t.env.StateDB.GetCode(addr))
				t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
					Opcode: op,
					Data:   &FramePair{(*hexutil.Big)(key.ToBig()), (*hexutil.Big)(hash.Big())},
				})
			}
		}
		if t.config.WithAccessList {
			addr := common.Address(stack[stackLen-1].Bytes20())
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				t.list.addAddress(addr)
			}
		}
	case vm.CALL, vm.STATICCALL, vm.DELEGATECALL, vm.CALLCODE:
		if stackLen < 5 {
			return
		}
		if t.config.WithAccessList {
			addr := common.Address(stack[stackLen-2].Bytes20())
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				t.list.addAddress(addr)
			}
		}

	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		size := int(op - vm.LOG0)
		if stackLen < size+2 {
			return
		}
		// Don't modify the stack
		mStart := stack[len(stack)-1]
		mSize := stack[len(stack)-2]
		topics := make([]common.Hash, size)
		for i := 0; i < size; i++ {
			topic := stack[len(stack)-2-(i+1)]
			topics[i] = topic.Bytes32()
		}
		data, err := tracers.GetMemoryCopyPadded(scope.Memory, int64(mStart.Uint64()), int64(mSize.Uint64()))
		if err != nil {
			// mSize was unrealistically large
			return
		}
		if t.config.WithFrame {
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Data: &FrameLog{
					Address: scope.Contract.Address(),
					Topics:  topics,
					Data:    data,
				},
			})
		}
	}
}

func (t *Tracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *Tracer) GetResult() (json.RawMessage, error) {
	res, err := json.Marshal(t.rootFrame)
	if err != nil {
		return nil, err
	}
	return res, t.reason
}

func (t *Tracer) Frame() *Frame {
	return t.rootFrame
}

// AccessList returns the current accesslist maintained by the tracer.
func (t *Tracer) AccessList() types.AccessList {
	return t.list.accessList()
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *Tracer) Stop(err error) {
	t.reason = err
	t.interrupt.Store(true)
}
