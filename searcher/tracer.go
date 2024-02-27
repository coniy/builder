package searcher

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/holiman/uint256"
	"math/big"
	"sync/atomic"
)

func (f *CallFrame) processOutput(output []byte, err error) {
	output = common.CopyBytes(output)
	if err == nil {
		f.Output = output
		return
	}
	f.Error = err.Error()
	if !errors.Is(err, vm.ErrExecutionReverted) || len(output) == 0 {
		return
	}
	f.Output = output
	if len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		f.RevertReason = unpacked
	}
}

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
	config    TracerConfig
	env       *vm.EVM
	callstack []*CallFrame
	gasLimit  uint64
	usedGas   uint64
	interrupt atomic.Bool // Atomic flag to signal execution interruption
	reason    error       // Textual reason for the interruption
	list      accessList  // Set of accounts and storage slots touched
	ops       []Operation
}

type TracerConfig struct {
	WithCall           bool                        `json:"withCall,omitempty"`
	WithLog            bool                        `json:"withLog,omitempty"`
	WithAccessList     bool                        `json:"withAccessList,omitempty"`
	AccessListExcludes map[common.Address]struct{} `json:"accessListExcludes,omitempty"`
	WithOpcode         bool                        `json:"withOpcode,omitempty"`
	WithMemory         bool                        `json:"withMemory,omitempty"`
	WithStack          bool                        `json:"withStack,omitempty"`
	WithStorage        bool                        `json:"withStorage,omitempty"`
	WithReturnData     bool                        `json:"withReturnData,omitempty"`
}

type Operation struct {
	PC            uint64                      `json:"pc"`
	Op            string                      `json:"op"`
	Gas           uint64                      `json:"gas"`
	GasCost       uint64                      `json:"gasCost,omitempty"`
	Memory        []byte                      `json:"memory,omitempty"`
	Stack         []uint256.Int               `json:"stack,omitempty"`
	ReturnData    []byte                      `json:"returnData,omitempty"`
	Storage       map[common.Hash]common.Hash `json:"storage,omitempty"`
	Depth         int                         `json:"depth,omitempty"`
	RefundCounter uint64                      `json:"refund,omitempty"`
	Error         string                      `json:"error,omitempty"`
}

// NewCombinedTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func NewCombinedTracer(config TracerConfig) *Tracer {
	// First callframe contains tx context info
	// and is populated on start and end.
	tracer := &Tracer{
		config:    config,
		callstack: []*CallFrame{{}},
	}
	if config.WithAccessList {
		tracer.list = newAccessList()
	}
	return tracer
}

func (t *Tracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *Tracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env
	if t.config.WithCall {
		t.callstack[0] = &CallFrame{
			Type:  CallType(vm.CALL.String()),
			From:  from,
			To:    to,
			Value: value,
			Gas:   t.gasLimit,
			Input: common.CopyBytes(input),
		}
		if create {
			t.callstack[0].Type = CallType(vm.CREATE.String())
		}
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *Tracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	if t.config.WithCall {
		t.callstack = append(t.callstack, &CallFrame{
			Type:  CallType(typ.String()),
			From:  from,
			To:    to,
			Value: value,
			Gas:   gas,
			Input: common.CopyBytes(input),
		})
	}
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *Tracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	stack := scope.Stack
	stackData := stack.Data()
	stackLen := len(stackData)

	if t.config.WithOpcode {
		// Copy a snapshot of the current memory state to a new buffer
		var mem []byte
		if t.config.WithMemory {
			mem = make([]byte, len(scope.Memory.Data()))
			copy(mem, scope.Memory.Data())
		}
		// Copy a snapshot of the current stack state to a new buffer
		var stck []uint256.Int
		if !t.config.WithStack {
			stck = make([]uint256.Int, stackLen)
			for i, item := range stackData {
				stck[i] = item
			}
		}

		// Copy a snapshot of the current storage to a new container
		var storage map[common.Hash]common.Hash
		if !t.config.WithStorage && (op == vm.SLOAD || op == vm.SSTORE) {
			// capture SLOAD opcodes and record the read entry in the local storage
			if op == vm.SLOAD && stackLen >= 1 {
				slot := common.Hash(stackData[stackLen-1].Bytes32())
				value := t.env.StateDB.GetState(scope.Contract.Address(), slot)
				storage = map[common.Hash]common.Hash{
					slot: value,
				}
			} else if op == vm.SSTORE && stackLen >= 2 {
				// capture SSTORE opcodes and record the written entry in the local storage.
				slot := common.Hash(stackData[stackLen-1].Bytes32())
				value := common.Hash(stackData[stackLen-2].Bytes32())
				storage = map[common.Hash]common.Hash{
					slot: value,
				}
			}
		}

		var rdata []byte
		if t.config.WithReturnData {
			rdata = make([]byte, len(rData))
			copy(rdata, rData)
		}

		var errString string
		if err != nil {
			errString = err.Error()
		}

		// create a new snapshot of the EVM.
		t.ops = append(t.ops, Operation{
			PC:            pc,
			Op:            op.String(),
			Gas:           gas,
			GasCost:       cost,
			Memory:        mem,
			Stack:         stck,
			ReturnData:    rdata,
			Storage:       storage,
			Depth:         depth,
			RefundCounter: t.env.StateDB.GetRefund(),
			Error:         errString,
		})
	}

	// Only logs need to be captured via opcode processing
	if t.config.WithLog {
		switch op {
		case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
			size := int(op - vm.LOG0)
			if stackLen >= size+2 {
				// Don't modify the stack
				mStart := stackData[len(stackData)-1]
				mSize := stackData[len(stackData)-2]
				topics := make([]common.Hash, size)
				for i := 0; i < size; i++ {
					topic := stackData[len(stackData)-2-(i+1)]
					topics[i] = topic.Bytes32()
				}

				data := scope.Memory.GetCopy(int64(mStart.Uint64()), int64(mSize.Uint64()))
				lastFrame := t.callstack[len(t.callstack)-1]
				lastFrame.Logs = append(lastFrame.Logs, &CallLog{
					Address: scope.Contract.Address(),
					Topics:  topics,
					Data:    data,
				})
			}
		}
	}
	if t.config.WithAccessList {
		if (op == vm.SLOAD || op == vm.SSTORE) && stackLen >= 1 {
			addr := scope.Contract.Address()
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				slot := common.Hash(stackData[stackLen-1].Bytes32())
				t.list.addSlot(addr, slot)
			}
		}
		if (op == vm.BALANCE || op == vm.EXTCODESIZE || op == vm.EXTCODECOPY || op == vm.EXTCODEHASH || op == vm.SELFDESTRUCT) && stackLen >= 1 {
			addr := common.Address(stackData[stackLen-1].Bytes20())
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				t.list.addAddress(addr)
			}
		}
		if (op == vm.CALL || op == vm.STATICCALL || op == vm.DELEGATECALL || op == vm.CALLCODE) && stackLen >= 5 {
			addr := common.Address(stackData[stackLen-2].Bytes20())
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				t.list.addAddress(addr)
			}
		}
	}
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *Tracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if t.config.WithCall {
		size := len(t.callstack)
		if size <= 1 {
			return
		}
		// pop call
		call := t.callstack[size-1]
		t.callstack = t.callstack[:size-1]
		size -= 1

		call.GasUsed = gasUsed
		call.processOutput(output, err)
		t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *Tracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	if t.config.WithCall {
		t.callstack[0].processOutput(output, err)
	}
}

func (t *Tracer) CaptureTxEnd(restGas uint64) {
	t.usedGas = t.gasLimit - restGas
	if t.config.WithCall {
		t.callstack[0].GasUsed = t.usedGas
	}
}

func (t *Tracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *Tracer) GetResult() (json.RawMessage, error) {
	if len(t.callstack) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}

	res, err := json.Marshal(t.callstack[0])
	if err != nil {
		return nil, err
	}
	return res, t.reason
}

func (t *Tracer) CallFrame() *CallFrame {
	return t.callstack[0]
}

// AccessList returns the current accesslist maintained by the tracer.
func (t *Tracer) AccessList() types.AccessList {
	return t.list.accessList()
}

func (t *Tracer) Operations() []Operation {
	return t.ops
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *Tracer) Stop(err error) {
	t.reason = err
	t.interrupt.Store(true)
}
