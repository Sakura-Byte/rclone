package fs

import (
	"fmt"
	"strings"
)

const (
	ListOrderDefault = "default"
	ListOrderReverse = "reverse"
	ListOrderRandom  = "random"
)

// ParseListOrder normalizes and validates a list order mode.
func ParseListOrder(order string) (string, error) {
	order = strings.ToLower(order)
	if order == "" {
		order = ListOrderDefault
	}
	switch order {
	case ListOrderDefault, ListOrderReverse, ListOrderRandom:
		return order, nil
	default:
		return "", fmt.Errorf("unknown --list-order %q (must be %q, %q, or %q)", order, ListOrderDefault, ListOrderReverse, ListOrderRandom)
	}
}
