package panel

// This read model is deliberately the Java ForwardWithTunnelDto wire shape.
// Typed scanning avoids allocating and sorting two maps per forwarding row.
type forwardListRow struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	InPort        int64   `json:"inPort"`
	RemoteAddr    string  `json:"remoteAddr"`
	EngineOptions *string `json:"engineOptions"`
	Engine        *string `json:"engine"`
	Status        int64   `json:"status"`
	CreatedTime   int64   `json:"createdTime"`
	UpdatedTime   *int64  `json:"updatedTime"`
	TunnelName    *string `json:"tunnelName"`
	InIP          *string `json:"inIp"`
	UserName      string  `json:"userName"`
	UserID        int64   `json:"userId"`
	TunnelID      int64   `json:"tunnelId"`
	InFlow        int64   `json:"inFlow"`
	OutFlow       int64   `json:"outFlow"`
	Strategy      string  `json:"strategy"`
	Inx           int64   `json:"inx"`
	InterfaceName *string `json:"interfaceName"`
}

func forwardListRows(s store, query string, args ...any) []forwardListRow {
	rows, e := s.q.QueryContext(s.ctx, query, args...)
	must(e)
	defer rows.Close()
	result := []forwardListRow{}
	for rows.Next() {
		var row forwardListRow
		must(rows.Scan(&row.ID, &row.Name, &row.InPort, &row.RemoteAddr, &row.EngineOptions, &row.Engine, &row.Status, &row.CreatedTime, &row.UpdatedTime, &row.TunnelName, &row.InIP, &row.UserName, &row.UserID, &row.TunnelID, &row.InFlow, &row.OutFlow, &row.Strategy, &row.Inx, &row.InterfaceName))
		result = append(result, row)
	}
	must(rows.Err())
	return result
}
