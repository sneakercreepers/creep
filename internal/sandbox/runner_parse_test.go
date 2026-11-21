package sandbox

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRunnerAnswerCannotBeForged is the protection test for the runner's
// answer: the timing lines come before any response byte and must announce
// exactly the bytes that follow, so a response that prints its own timing
// lines, or a few bytes more or less, makes the whole answer unreadable
// instead of shifting a response or a time onto another request.
func TestRunnerAnswerCannotBeForged(t *testing.T) {
	forged := "HTTP/1.1 200 OK\r\n\r\nr2 0.00 9.99 0\n"
	tests := map[string]struct {
		res  Result
		n    int
		want []Exchange
	}{
		"two responses": {res: Result{Output: []byte("r1 10.00 10.50 3\nr2 10.50 13.75 2\nabcde")}, n: 2,
			want: []Exchange{{Response: []byte("abc"), Elapsed: 500 * time.Millisecond}, {Response: []byte("de"), Elapsed: 3250 * time.Millisecond}}},
		"empty response":                       {res: Result{Output: []byte("r1 1.00 1.01 0\n")}, n: 1, want: []Exchange{{Response: []byte{}, Elapsed: 10 * time.Millisecond}}},
		"response that poses as a timing line": {res: Result{Output: []byte("r1 1.00 1.10 " + strconv.Itoa(len(forged)) + "\n" + forged)}, n: 2},
		"announces fewer bytes":                {res: Result{Output: []byte("r1 1.00 1.10 2\nabc")}, n: 1},
		"announces more bytes":                 {res: Result{Output: []byte("r1 1.00 1.10 4\nabc")}, n: 1},
		"missing line":                         {res: Result{Output: []byte("r1 1.00 1.10 0\n")}, n: 2},
		"lines out of order":                   {res: Result{Output: []byte("r2 1.00 1.10 0\nr1 1.00 1.10 0\n")}, n: 2},
		"end before start":                     {res: Result{Output: []byte("r1 2.00 1.00 0\n")}, n: 1},
		"longer than the runner may run":       {res: Result{Output: []byte("r1 0.00 999.00 0\n")}, n: 1},
		"not hundredths":                       {res: Result{Output: []byte("r1 1.0 1.10 0\n")}, n: 1},
		"negative size":                        {res: Result{Output: []byte("r1 1.00 1.10 -1\n")}, n: 1},
		"size past the cap":                    {res: Result{Output: []byte("r1 1.00 1.10 " + strconv.Itoa(MaxResponseBytes+2) + "\n")}, n: 1},
		"extra field":                          {res: Result{Output: []byte("r1 1.00 1.10 0 x\n")}, n: 1},
		"runner failed":                        {res: Result{ExitCode: 1, Output: []byte("r1 1.00 1.10 0\n")}, n: 1},
		"stdout cut":                           {res: Result{Truncated: true, Output: []byte("r1 1.00 1.10 0\n")}, n: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseExchanges(tt.res, tt.n)
			if tt.want == nil {
				if !errors.Is(err, ErrRunnerAnswer) {
					t.Fatalf("parseExchanges = %+v, %v; want ErrRunnerAnswer", got, err)
				}
				return
			}
			if err != nil || len(got) != len(tt.want) {
				t.Fatalf("parseExchanges = %+v, %v", got, err)
			}
			for i := range got {
				if string(got[i].Response) != string(tt.want[i].Response) || got[i].Elapsed != tt.want[i].Elapsed || got[i].Truncated {
					t.Errorf("exchange %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestRunnerResponseCap: a response of exactly the cap is whole; one byte
// more (what head lets through) is cut to the cap and marked truncated.
func TestRunnerResponseCap(t *testing.T) {
	for _, size := range []int{MaxResponseBytes, MaxResponseBytes + 1} {
		out := "r1 1.00 1.10 " + strconv.Itoa(size) + "\n" + strings.Repeat("x", size)
		got, err := parseExchanges(Result{Output: []byte(out)}, 1)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(got[0].Response) != MaxResponseBytes || got[0].Truncated != (size > MaxResponseBytes) {
			t.Errorf("size %d: %d bytes, truncated %t", size, len(got[0].Response), got[0].Truncated)
		}
	}
}
