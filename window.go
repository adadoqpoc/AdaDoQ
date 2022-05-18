package main

import (
	"time"
)

type Window struct {
	curScore   float64
	prvScore   float64
	lastUpdate time.Time
}
