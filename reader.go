package ftrace

import (
	"bufio"
	"os"
)

func Reader(filename string) (chan string, error) {
	fp, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	out := make(chan string)
	go func() {
		defer fp.Close()
		// we need to close the out channel in order
		// to signal the end-of-data condition
		defer close(out)
		scanner := bufio.NewScanner(fp)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			out <- scanner.Text()
		}
	}()

	return out, nil
}
