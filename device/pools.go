/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"sync"
)

// DefaultMessageBufferPoolLimit bounds packet memory retained by one Device.
// A message buffer is MaxMessageSize bytes; an unlimited pool can grow with a
// sustained packet backlog.
const DefaultMessageBufferPoolLimit uint32 = 4096

type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count uint32 // Get calls not yet Put back
	max   uint32
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get()
}

// TryGet gets an item without waiting for capacity. Packet workers must use it
// so overload is handled by dropping a packet, not by blocking the worker.
func (p *WaitPool) TryGet() (any, bool) {
	if p.max != 0 {
		p.lock.Lock()
		if p.count >= p.max {
			p.lock.Unlock()
			return nil, false
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get(), true
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	p.cond.Signal()
}

func (p *WaitPool) setMax(max uint32) {
	p.lock.Lock()
	p.max = max
	p.cond.Broadcast()
	p.lock.Unlock()
}

func (p *WaitPool) stats() (inUse, limit uint32) {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.count, p.max
}

func (device *Device) PopulatePools() {
	device.pool.inboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueInboundElement, 0, device.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	})
	device.pool.outboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueOutboundElement, 0, device.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	})
	device.pool.messageBuffers = NewWaitPool(DefaultMessageBufferPoolLimit, func() any {
		return new([MaxMessageSize]byte)
	})
	device.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	device.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
}

func (device *Device) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := device.pool.inboundElementsContainer.Get().(*QueueInboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c
}

func (device *Device) PutInboundElementsContainer(c *QueueInboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.inboundElementsContainer.Put(c)
}

func (device *Device) GetOutboundElementsContainer() *QueueOutboundElementsContainer {
	c := device.pool.outboundElementsContainer.Get().(*QueueOutboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c
}

func (device *Device) PutOutboundElementsContainer(c *QueueOutboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.outboundElementsContainer.Put(c)
}

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (device *Device) tryGetMessageBuffer() (*[MaxMessageSize]byte, bool) {
	msg, ok := device.pool.messageBuffers.TryGet()
	if !ok {
		return nil, false
	}
	return msg.(*[MaxMessageSize]byte), true
}

// SetMessageBufferPoolLimit configures a finite per-device packet-memory
// budget. Call it before Up. Zero is deliberately rejected: it was the
// upstream default and permits unbounded retained memory.
func (device *Device) SetMessageBufferPoolLimit(limit uint32) error {
	minimum := uint32(device.BatchSize() * 3)
	if limit < minimum {
		return fmt.Errorf("message buffer pool limit %d is below the minimum %d", limit, minimum)
	}
	device.pool.messageBuffers.setMax(limit)
	return nil
}

type MessageBufferPoolStats struct {
	InUse           uint32
	Limit           uint32
	InboundDropped  uint64
	OutboundDropped uint64
}

// MessageBufferPoolStats returns the current buffer budget and overload drops.
func (device *Device) MessageBufferPoolStats() MessageBufferPoolStats {
	inUse, limit := device.pool.messageBuffers.stats()
	return MessageBufferPoolStats{
		InUse: inUse, Limit: limit,
		InboundDropped:  device.metrics.inboundDropped.Load(),
		OutboundDropped: device.metrics.outboundDropped.Load(),
	}
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
