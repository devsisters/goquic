package goquic

type BytesBufferPool struct {
	c        chan []byte
	poolsize int
	bufsize  int
}

func NewBytesBufferPool(poolsize int, bufsize int) (bp *BytesBufferPool) {
	return &BytesBufferPool{
		c:        make(chan []byte, poolsize),
		poolsize: poolsize,
		bufsize:  bufsize,
	}
}

func (bp *BytesBufferPool) Get() (b []byte) {
	select {
	case b = <-bp.c:
		// reuse existing buffer
	default:
		// create new buffer
		b = make([]byte, bp.bufsize)
	}
	return
}

func (bp *BytesBufferPool) Put(b []byte) {
	select {
	case bp.c <- b:
	default: // Discard the buffer if the pool is full.
	}
}
