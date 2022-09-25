package cachemap

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type CacheMap struct {
	mu       sync.RWMutex
	m        map[string]Item
	ctx      context.Context
	interval time.Duration
}

type DeleteFunc func(key string, item Item)

type ForeachFunc func(key string, item Item)

type Item struct {
	Value      interface{}
	TTL        time.Duration
	AddTime    time.Time
	DeleteTime time.Time
	DeleteFunc DeleteFunc
}

type Config struct {
	Key        string
	Value      interface{}
	TTL        time.Duration
	DeleteFunc DeleteFunc
}

var (
	ErrorKeyIsNil    = fmt.Errorf("key is nil")
	ErrorKeyExist    = fmt.Errorf("key exist")
	ErrorKeyNotFound = fmt.Errorf("key not found")
)

func New(ctx context.Context, interval time.Duration) *CacheMap {
	c := &CacheMap{
		mu:       sync.RWMutex{},
		m:        map[string]Item{},
		ctx:      ctx,
		interval: interval,
	}
	if c.ctx == nil {
		c.ctx = context.Background()
	}
	if c.interval < 1*time.Second {
		c.interval = 1 * time.Second
	}
	return c
}

func (c *CacheMap) autoDelete() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(c.interval):
			c.mu.Lock()
			for key, item := range c.m {
				if time.Now().After(item.DeleteTime) {
					if item.DeleteFunc != nil {
						item.DeleteFunc(key, item)
					}
					delete(c.m, key)
				}
			}
			c.mu.Unlock()
		}
	}
}

func checkConfig(config *Config) error {
	if config.Key == "" {
		return ErrorKeyIsNil
	}
	if config.TTL <= 0 {
		config.TTL = -1
	}
	return nil
}

func (c *CacheMap) Exist(key string) bool {
	if key == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.m[key]
	if !ok {
		return false
	} else {
		if time.Now().After(item.DeleteTime) {
			if item.DeleteFunc != nil {
				item.DeleteFunc(key, item)
			}
			delete(c.m, key)
			return false
		}
		return true
	}
}

func (c *CacheMap) Set(config Config) error {
	err := checkConfig(&config)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if i, ok := c.m[config.Key]; ok {
		if time.Now().Before(i.DeleteTime) {
			return ErrorKeyExist
		} else {
			if i.DeleteFunc != nil {
				i.DeleteFunc(config.Key, i)
			}
			delete(c.m, config.Key)
		}
	}
	item := Item{
		Value:      config.Value,
		TTL:        config.TTL,
		AddTime:    time.Now(),
		DeleteFunc: config.DeleteFunc,
	}
	item.DeleteTime = item.AddTime.Add(item.TTL)
	c.m[config.Key] = item
	return nil
}

func (c *CacheMap) Get(key string) (Item, bool) {
	if key == "" {
		return Item{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.m[key]
	if !ok {
		return Item{}, false
	} else if time.Now().After(item.DeleteTime) {
		if item.DeleteFunc != nil {
			item.DeleteFunc(key, item)
		}
		delete(c.m, key)
		return Item{}, false
	} else {
		return item, true
	}
}

func (c *CacheMap) Delete(key string) error {
	if key == "" {
		return ErrorKeyIsNil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.m[key]
	if !ok {
		return ErrorKeyNotFound
	}
	if item.DeleteFunc != nil {
		item.DeleteFunc(key, item)
	}
	delete(c.m, key)
	return nil
}

func (c *CacheMap) SetValue(key string, value interface{}) error {
	if key == "" {
		return ErrorKeyIsNil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.m[key]
	if !ok {
		return ErrorKeyNotFound
	}
	if time.Now().After(item.DeleteTime) {
		if item.DeleteFunc != nil {
			item.DeleteFunc(key, item)
		}
		delete(c.m, key)
		return ErrorKeyNotFound
	}
	item.Value = value
	c.m[key] = item
	return nil
}

func (c *CacheMap) SetTTL(key string, ttl time.Duration) error {
	if key == "" {
		return ErrorKeyIsNil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.m[key]
	if !ok {
		return ErrorKeyNotFound
	}
	if time.Now().After(item.DeleteTime) {
		if item.DeleteFunc != nil {
			item.DeleteFunc(key, item)
		}
		delete(c.m, key)
		return ErrorKeyNotFound
	}
	item.TTL = ttl
	item.DeleteTime = time.Now().Add(ttl)
	c.m[key] = item
	return nil
}

func (c *CacheMap) SetDeleteFunc(key string, deleteFunc DeleteFunc) error {
	if key == "" {
		return ErrorKeyIsNil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.m[key]
	if !ok {
		return ErrorKeyNotFound
	}
	if time.Now().After(item.DeleteTime) {
		if item.DeleteFunc != nil {
			item.DeleteFunc(key, item)
		}
		delete(c.m, key)
		return ErrorKeyNotFound
	}
	item.DeleteFunc = deleteFunc
	c.m[key] = item
	return nil
}

func (c *CacheMap) Foreach(f ForeachFunc) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for key, item := range c.m {
		if time.Now().After(item.DeleteTime) {
			if item.DeleteFunc != nil {
				item.DeleteFunc(key, item)
			}
			delete(c.m, key)
		} else {
			f(key, item)
		}
	}
}
