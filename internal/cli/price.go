package cli

import "fmt"

// pricing turns tokens into money for estimate and --stats. Prices come
// only from --price-in and --price-out, per 1M tokens, in whatever currency
// the user reads them in; creep ships no price table that could go stale.
type pricing struct {
	in, out float64 // per 1M tokens; both 0 means not set
	// quota is the command contract: a subscription CLI spends the user's
	// quota, not money per token, so calls and tokens are what count.
	quota bool
}

func pricingFor(o globalOptions, contract string) pricing {
	return pricing{in: o.priceIn, out: o.priceOut, quota: contract == "command"}
}

// cost is the money in and out tokens cost, or why it is not computed.
func (p pricing) cost(in, out int) string {
	switch {
	case p.quota:
		return "not computed: the command contract spends your subscription quota (see calls and tokens)"
	case p.in == 0 && p.out == 0:
		return "not computed: set --price-in and --price-out (price per 1M tokens)"
	}
	total := float64(in)/1e6*p.in + float64(out)/1e6*p.out
	return fmt.Sprintf("%.4f (at %g in, %g out per 1M tokens)", total, p.in, p.out)
}
