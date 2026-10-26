package engine

import "fmt"

func settleMaintenancePages(report Report, settle func(Report) (Acknowledgement, error)) (Acknowledgement, error) {
	pages := (len(report.Usage) + 9999) / 10000
	if pages < 1 {
		pages = 1
	}
	var last Acknowledgement
	for index := 0; index < pages; index++ {
		part := report
		part.Sequence = report.Sequence - int64(pages-1-index)
		start := index * 10000
		end := min(start+10000, len(report.Usage))
		part.Usage = report.Usage[start:end]
		part.Leases = nil
		ids := map[string]bool{}
		for _, u := range part.Usage {
			ids[u.ID] = true
		}
		for _, l := range report.Leases {
			if ids[l.ServiceID] || pages == 1 {
				part.Leases = append(part.Leases, l)
			}
		}
		ack, e := settle(part)
		if e != nil {
			return last, e
		}
		if ack.Epoch != part.Epoch || ack.Sequence != part.Sequence || !ack.MaintenanceAccepted {
			return last, fmt.Errorf("maintenance page was not acknowledged")
		}
		last = ack
	}
	return last, nil
}
