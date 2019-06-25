// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package processor

import (
	"log"

	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
)

const queueNumRetries = 3

type Controller struct {
	configStoreCache model.ConfigStoreCache
	queue            workqueue.RateLimitingInterface
}

type op string

const (
	CREATE op = "CREATE"
	UPDATE op = "UPDATE"
	DELETE op = "DELETE"
)

type OnErrorFunc func(err error, item *Item) error

type Item struct {
	Operation    op
	Resource     model.Config
	ErrorHandler OnErrorFunc
}

// NewController is responsible for creating the processing controller workqueue
func NewController(configStoreCache model.ConfigStoreCache) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	c := &Controller{
		configStoreCache: configStoreCache,
		queue:            queue,
	}

	return c
}

// ProcessConfigChange is responsible for adding the key of the item to the queue
func (c *Controller) ProcessConfigChange(item *Item) {
	log.Printf("Processor: ProcessConfigChange() Item added to queue Resource: %s, Action: %s", item.Resource.Key(), item.Operation)
	c.queue.Add(item)
}

// Run starts the main controller loop running sync at every poll interval.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	wait.Until(c.runWorker, 0, stopCh)
}

// runWorker calls processNextItem to process events of the work queue
func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem takes an item off the queue and calls the controllers sync
// function, handles the logic of re-queuing in case any errors occur
func (c *Controller) processNextItem() bool {
	itemObj, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(itemObj)

	item, ok := itemObj.(*Item)
	if !ok {
		log.Printf("Processor: processNextItem() Item cast failed for resource %v", item)
		return true
	}

	log.Printf("Processor: processNextItem() Processing %s for resource: %s", item.Operation, item.Resource.Key())
	err := c.sync(item)
	if err != nil {
		log.Printf("Processor: processNextItem() Error performing %s for resource: %s: %s", item.Operation, item.Resource.Key(), err)
		if item.ErrorHandler != nil {
			err := item.ErrorHandler(err, item)
			if err != nil && c.queue.NumRequeues(itemObj) < queueNumRetries {
				log.Printf("Processor: processNextItem() Retrying %s for resource: %s due to sync error", item.Operation, item.Resource.Key())
				c.queue.AddRateLimited(itemObj)
				return true
			}
		}
	}

	c.queue.Forget(itemObj)
	return true
}

// sync is responsible for invoking the appropriate API operation on the model.Config resource
func (c *Controller) sync(item *Item) error {

	if item == nil {
		return nil
	}

	var err error
	switch item.Operation {
	case CREATE:
		_, err = c.configStoreCache.Create(item.Resource)
	case UPDATE:
		_, err = c.configStoreCache.Update(item.Resource)
	case DELETE:
		res := item.Resource
		err = c.configStoreCache.Delete(res.Type, res.Name, res.Namespace)
	}

	return err
}
