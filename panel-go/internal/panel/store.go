package panel

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

type M map[string]any
type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}
type store struct {
	q   querier
	ctx context.Context
}

func (s store) rows(query string, args ...any) []M {
	rows, err := s.q.QueryContext(s.ctx, query, args...)
	must(err)
	defer rows.Close()
	cols, err := rows.Columns()
	must(err)
	types, err := rows.ColumnTypes()
	must(err)
	result := []M{}
	names := make([]string, len(cols))
	numeric := make([]bool, len(cols))
	vals := make([]any, len(cols))
	ptr := make([]any, len(cols))
	for i := range cols {
		names[i] = camel(cols[i])
		ptr[i] = &vals[i]
		switch types[i].DatabaseTypeName() {
		case "DECIMAL", "NEWDECIMAL", "BIGINT", "INT", "TINYINT", "SMALLINT", "MEDIUMINT", "FLOAT", "DOUBLE":
			numeric[i] = true
		}
	}
	for rows.Next() {
		must(rows.Scan(ptr...))
		r := make(M, len(cols))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				text := string(b)
				if numeric[i] {
					v = json.Number(text)
				} else {
					v = text
				}
			}
			r[names[i]] = v
		}
		result = append(result, r)
	}
	must(rows.Err())
	return result
}
func (s store) one(query string, args ...any) M {
	r := s.rows(query, args...)
	if len(r) == 0 {
		return nil
	}
	return r[0]
}
func (s store) exec(query string, args ...any) sql.Result {
	r, e := s.q.ExecContext(s.ctx, query, args...)
	must(e)
	return r
}
func (s store) get(table string, id any) M {
	validTable(table)
	return s.one("SELECT * FROM `"+table+"` WHERE id=?", id)
}
func validTable(t string) {
	switch t {
	case "user", "node", "tunnel", "forward", "user_tunnel", "speed_limit", "vite_config", "statistics_flow":
		return
	}
	panic("invalid internal table")
}
func (s store) insert(table string, m M) int64 {
	validTable(table)
	keys := keysOf(m)
	cols := []string{}
	args := []any{}
	marks := []string{}
	for _, k := range keys {
		cols = append(cols, "`"+snake(k)+"`")
		args = append(args, m[k])
		marks = append(marks, "?")
	}
	r := s.exec("INSERT INTO `"+table+"` ("+strings.Join(cols, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...)
	id, e := r.LastInsertId()
	must(e)
	return id
}
func (s store) update(table string, id any, m M) {
	validTable(table)
	if len(m) == 0 {
		return
	}
	sets := []string{}
	args := []any{}
	for _, k := range keysOf(m) {
		sets = append(sets, "`"+snake(k)+"`=?")
		args = append(args, m[k])
	}
	args = append(args, id)
	s.exec("UPDATE `"+table+"` SET "+strings.Join(sets, ",")+" WHERE id=?", args...)
}
func (s store) remove(table string, id any) {
	validTable(table)
	s.exec("DELETE FROM `"+table+"` WHERE id=?", id)
}
func (p *Panel) transaction(ctx context.Context, fn func(store) any) (result any) {
	tx, e := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	must(e)
	defer tx.Rollback()
	result = fn(store{tx, ctx})
	must(tx.Commit())
	return
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func camel(s string) string {
	a := strings.Split(s, "_")
	for i := 1; i < len(a); i++ {
		if a[i] != "" {
			a[i] = strings.ToUpper(a[i][:1]) + a[i][1:]
		}
	}
	return strings.Join(a, "")
}
func snake(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func keysOf(m M) []string {
	k := []string{}
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}
func pick(m M, keys string) M {
	r := M{}
	for _, k := range strings.Fields(keys) {
		if v, ok := m[k]; ok && v != nil {
			r[k] = v
		}
	}
	return r
}
func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func num(v any) int64 {
	switch v := v.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		if v != float64(int64(v)) {
			fail("integer required")
		}
		return int64(v)
	default:
		if v == nil {
			return 0
		}
		n, e := strconv.ParseInt(str(v), 10, 64)
		if e != nil {
			r, ok := new(big.Rat).SetString(str(v))
			if !ok || !r.IsInt() || !r.Num().IsInt64() {
				fail("integer required")
			}
			n = r.Num().Int64()
		}

		return n
	}
}
func now() int64 { return time.Now().UnixMilli() }
func defaults(m M, d M) M {
	for k, v := range d {
		if m[k] == nil {
			m[k] = v
		}
	}
	return m
}
func require(m M, keys string) {
	for _, k := range strings.Fields(keys) {
		if m[k] == nil || strings.TrimSpace(str(m[k])) == "" {
			fail(k + "不能为空")
		}
	}
}

type apiError struct {
	Message string
	Code    int
	Status  int
}

func fail(s string)                    { panic(apiError{s, -1, 200}) }
func statusError(status int, s string) { panic(apiError{s, status, status}) }

func project(m M, keys string) M {
	out := M{}
	for _, k := range strings.Fields(keys) {
		out[k] = m[k]
	}
	return out
}

// Request cancellation must not leave an advisory lock on an idle pooled connection.
func releaseNamedLock(conn *sql.Conn, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var released sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT RELEASE_LOCK(?)", key).Scan(&released); err != nil || !released.Valid || released.Int64 != 1 {
		// Discarding the physical session also releases any server-side named lock.
		conn.Raw(func(any) error { return driver.ErrBadConn })
	}
}
