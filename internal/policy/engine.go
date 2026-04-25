package policy

import "github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"

type Rule struct {
	Condition func(models.KernelEvent) bool
	Response  models.ResponseLevel
}

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine {
	return &Engine{
		rules: []Rule{
			{
				Condition: func(e models.KernelEvent) bool {
					blacklist := map[string]bool{
						"nc": true, "ncat": true, "nmap": true, "hydra": true,
						"sqlmap": true, "john": true, "hashcat": true,
						"mimikatz": true, "metasploit": true,
					}
					return blacklist[e.Comm]
				},
				Response: models.L3Kill,
			},
			{
				Condition: func(e models.KernelEvent) bool {
					return e.Confidence >= 0.9
				},
				Response: models.L3Kill,
			},
			{
				Condition: func(e models.KernelEvent) bool {
					monitored := map[string]bool{"curl": true, "wget": true, "bash": true, "python3": true}
					return monitored[e.Comm] || e.Confidence >= 0.7
				},
				Response: models.L2Contain,
			},
		},
	}
}

func (e *Engine) Evaluate(ev models.KernelEvent) models.ResponseLevel {
	for _, r := range e.rules {
		if r.Condition(ev) {
			return r.Response
		}
	}
	return models.L1Monitor
}
