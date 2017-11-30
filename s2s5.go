package main

import (
	"fmt"
	"./cryptop"
)

func main() {
	fmt.Println(cryptop.ParseCookie("foo=bar&baz=qux&zap=zazzle"))
	fmt.Println(cryptop.GenProfileByEmail("b=lah@&meh.com",false))
}
