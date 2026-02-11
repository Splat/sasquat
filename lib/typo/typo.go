package typo

import (
	"log/slog"
	"strings"
	"zntr.io/typogenerator"
	"zntr.io/typogenerator/mapping"
	"zntr.io/typogenerator/strategy"
)

// Generate returns candidate lookalike domains for a given base domain (e.g., "example.com").
// It generates variants for the registrable label (SLD) and applies TLD variants.
// Leverages the typogenerator library for creating any number of potential matches to lookup
func Generate(domain string, cfg []strategy.Strategy, logger slog.Logger) ([]typogenerator.FuzzResult, error) {
	sld, tld, ok := splitSLDTLD(domain)
	logger.Info("processing domain Generate", "second level domain (sld)", sld)
	logger.Info("processing domain Generate", "top level domain (tld)", tld)
	if !ok {
		return nil, ErrInvalidDomain
	}

	// default cfg to use
	if cfg == nil || len(cfg) == 0 {
		cfg = []strategy.Strategy{
			strategy.Addition,
			strategy.BitSquatting,
			strategy.DoubleHit(mapping.English),
			strategy.Homoglyph,
			strategy.Hyphenation,
			strategy.Omission,
			strategy.Prefix,
			strategy.Repetition,
			strategy.Replace(mapping.English),
			strategy.Similar(mapping.English),
			strategy.SubDomain,
			strategy.TLDRepeat,
			strategy.TLDReplace,
			strategy.Transposition,
			strategy.VowelSwap,
		}
	}

	results, err := typogenerator.Fuzz(sld, cfg...)
	if err != nil {
		return results, err
	}

	for _, r := range results {
		for _, p := range r.Permutations {
			logger.Debug("processing result Generate", "domain", r.Domain, "strategy", r.StrategyName, "permutation", p)
		}
	}

	return results, nil
}

var ErrInvalidDomain = errorString("invalid domain; expected form: <label>.<tld>")

type errorString string

func (e errorString) Error() string { return string(e) }

func splitSLDTLD(domain string) (sld, tld string, ok bool) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", "", false
	}
	sld = parts[len(parts)-2]
	tld = parts[len(parts)-1]
	// very lightweight sanity checks; real-world registrable domain parsing is more complex
	if sld == "" || tld == "" {
		return "", "", false
	}
	return sld, strings.ToLower(tld), true
}
