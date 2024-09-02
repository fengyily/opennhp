package utils

import (
	"fmt"
	"math/rand"
	"runtime/debug"
	"strings"
	"time"

	"github.com/OpenNHP/opennhp/log"
)

func GetRandomUint32() (r uint32) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		r = rng.Uint32()
		if r != 0 {
			break
		}
	}
	return r
}

func CatchPanic() {
	if x := recover(); x != nil {
		for _, line := range append([]string{fmt.Sprint(x)}, strings.Split(string(debug.Stack()), "\n")...) {
			if len(strings.TrimSpace(line)) > 0 {
				log.Error(line)
			}
		}
	}
}

func CatchPanicThenRun(catchFun func()) {
	if x := recover(); x != nil {
		for _, line := range append([]string{fmt.Sprint(x)}, strings.Split(string(debug.Stack()), "\n")...) {
			if len(strings.TrimSpace(line)) > 0 {
				log.Error(line)
			}
		}
		if catchFun != nil {
			catchFun()
		}
	}
}
