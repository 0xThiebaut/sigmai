package api

import (
	"fmt"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/api/workers"
)

type Options struct {
	WorkerOptions *workers.Options
	Workers       int
}

func (o *Options) Validate() error {
	if o.Workers <= 1 {
		return fmt.Errorf("not enough workers, minimum is 2, got %d", o.Workers)
	}
	return nil
}
