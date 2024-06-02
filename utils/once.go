package utils

import "sync"

type Once[T any] struct {
	once  sync.Once
	value T
}

func (o *Once[T]) Do(f func() T) T {
	o.once.Do(func() {
		o.value = f()
	})
	return o.value
}
