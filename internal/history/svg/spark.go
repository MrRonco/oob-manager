package svg

import (
	"math"
	"strconv"
	"time"

	"oob-manager/internal/store"
)

// Spark is a sparkline's geometry: the averages over its window, no axes.
type Spark struct {
	ViewBox string
	D       string
	Points  int
}

// Sparkline draws buckets of step over [from, to) in a SparkW × SparkH box, 1 unit of
// padding; a gap of more than 2.5 steps breaks the line. Empty when there are no buckets.
func Sparkline(bs []store.Bucket, from, to time.Time, step time.Duration) Spark {
	sp := Spark{ViewBox: "0 0 " + strconv.Itoa(SparkW) + " " + strconv.Itoa(SparkH), Points: len(bs)}
	if len(bs) == 0 {
		return sp
	}
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, b := range bs {
		lo, hi = math.Min(lo, b.Avg), math.Max(hi, b.Avg)
	}
	ts := timeScale{from: from, to: to, x0: 1, x1: SparkW - 1}
	vs := valueScale{lo: lo, hi: hi, y0: 1, y1: SparkH - 1}
	sp.D = path(Series{Buckets: bs, Step: step}, ts, vs)
	return sp
}
