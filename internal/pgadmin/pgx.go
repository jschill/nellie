package pgadmin

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// NewConnector returns a Connector that connects using dsn, which may be a
// URL or a keyword/value connection string. Settings not present in dsn are
// taken from the standard libpq environment variables (PGHOST, PGUSER, ...).
func NewConnector(dsn string) (Connector, error) {
	base, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid connection string: %w", err)
	}
	return func(ctx context.Context, database string) (DB, error) {
		cfg := base.Copy()
		if database != "" {
			cfg.Database = database
		}
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return pgxDB{conn}, nil
	}, nil
}

type pgxDB struct {
	conn *pgx.Conn
}

func (d pgxDB) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := d.conn.Exec(ctx, sql, args...)
	return err
}

func (d pgxDB) Query(ctx context.Context, sql string, args ...any) ([][]string, error) {
	rows, err := d.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			if v != nil {
				row[i] = fmt.Sprint(v)
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (d pgxDB) Close(ctx context.Context) error {
	return d.conn.Close(ctx)
}
