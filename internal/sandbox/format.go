package sandbox

import "strconv"

func formatFixed(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}

func formatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
