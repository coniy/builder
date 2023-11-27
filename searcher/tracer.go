package searcher

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
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

var _ tracers.Tracer = (*combinedTracer)(nil)

type combinedTracer struct {
	callstack []*CallFrame
	config    combinedTracerConfig
	gasLimit  uint64
	interrupt atomic.Bool                 // Atomic flag to signal execution interruption
	reason    error                       // Textual reason for the interruption
	excl      map[common.Address]struct{} // Set of account to exclude from the list
	list      accessList                  // Set of accounts and storage slots touched
}

type combinedTracerConfig struct {
	WithCall       bool
	WithLog        bool
	WithAccessList bool
	From           common.Address
	To             common.Address
	PreCompiles    []common.Address
}

// newCallTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func newCombinedTracer(config combinedTracerConfig) *combinedTracer {
	// First callframe contains tx context info
	// and is populated on start and end.
	tracer := &combinedTracer{
		config:    config,
		callstack: []*CallFrame{{}},
	}
	if config.WithAccessList {
		tracer.excl = map[common.Address]struct{}{
			config.From: {},
			config.To:   {},
		}
		for _, addr := range config.PreCompiles {
			tracer.excl[addr] = struct{}{}
		}
		tracer.list = newAccessList()
	}
	return tracer
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *combinedTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	if t.config.WithCall {
		t.callstack[0] = &CallFrame{
			Type:  CallType(vm.CALL.String()),
			From:  from,
			To:    to,
			Value: (*hexutil.Big)(value),
			Gas:   hexutil.Uint64(t.gasLimit),
			Input: common.CopyBytes(input),
		}
		if create {
			t.callstack[0].Type = CallType(vm.CREATE.String())
		}
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *combinedTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	if t.config.WithCall {
		t.callstack[0].processOutput(output, err)
	}
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *combinedTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// skip if the previous op caused an error
	if err != nil {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}
	// Only logs need to be captured via opcode processing
	if t.config.WithLog {
		switch op {
		case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
			size := int(op - vm.LOG0)

			stack := scope.Stack
			stackData := stack.Data()

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
	if t.config.WithAccessList {
		stack := scope.Stack
		stackData := stack.Data()
		stackLen := len(stackData)
		if (op == vm.SLOAD || op == vm.SSTORE) && stackLen >= 1 {
			slot := common.Hash(stackData[stackLen-1].Bytes32())
			t.list.addSlot(scope.Contract.Address(), slot)
		}
		if (op == vm.EXTCODECOPY || op == vm.EXTCODEHASH || op == vm.EXTCODESIZE || op == vm.BALANCE || op == vm.SELFDESTRUCT) && stackLen >= 1 {
			addr := common.Address(stackData[stackLen-1].Bytes20())
			if _, ok := t.excl[addr]; !ok {
				t.list.addAddress(addr)
			}
		}
		if (op == vm.DELEGATECALL || op == vm.CALL || op == vm.STATICCALL || op == vm.CALLCODE) && stackLen >= 5 {
			addr := common.Address(stackData[stackLen-2].Bytes20())
			if _, ok := t.excl[addr]; !ok {
				t.list.addAddress(addr)
			}
		}
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *combinedTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	if t.config.WithCall {
		t.callstack = append(t.callstack, &CallFrame{
			Type:  CallType(typ.String()),
			From:  from,
			To:    to,
			Value: (*hexutil.Big)(value),
			Gas:   hexutil.Uint64(gas),
			Input: common.CopyBytes(input),
		})
	}
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *combinedTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if t.config.WithCall {
		size := len(t.callstack)
		if size <= 1 {
			return
		}
		// pop call
		call := t.callstack[size-1]
		t.callstack = t.callstack[:size-1]
		size -= 1

		call.GasUsed = hexutil.Uint64(gasUsed)
		call.processOutput(output, err)
		t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
	}
}

func (t *combinedTracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

func (t *combinedTracer) CaptureTxEnd(restGas uint64) {
	if t.config.WithCall {
		t.callstack[0].GasUsed = hexutil.Uint64(t.gasLimit - restGas)
	}
}

func (t *combinedTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *combinedTracer) GetResult() (json.RawMessage, error) {
	if len(t.callstack) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}

	res, err := json.Marshal(t.callstack[0])
	if err != nil {
		return nil, err
	}
	return res, t.reason
}

func (t *combinedTracer) CallFrame() *CallFrame {
	return t.callstack[0]
}

// AccessList returns the current accesslist maintained by the tracer.
func (a *combinedTracer) AccessList() types.AccessList {
	return a.list.accessList()
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *combinedTracer) Stop(err error) {
	t.reason = err
	t.interrupt.Store(true)
}
