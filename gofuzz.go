//+build gofuzz

package ospf3

func Fuzz(b []byte) int { return fuzz(b) }
