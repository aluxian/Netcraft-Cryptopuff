package database

import (
	"math"
	"math/rand"
	"time"
)

const (
	cMax  = 8
	scale = 10 * time.Millisecond
)

func BinaryExponentialBackoff() func(try int) time.Duration {
	return func(try int) time.Duration {
		c := rand.Intn(cMax)
		if c < try {
			c = try
		}
		return time.Duration(math.Pow(2, float64(c)) * float64(scale))
	}
}
