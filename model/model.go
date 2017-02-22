package model

import "time"

// OsqueryItem represents an osqueryi query result set
type OsqueryItem map[string]string

// OsqueryResults represents an osqueryi call result
type OsqueryResult struct {
	Items   []OsqueryItem
	Runtime time.Duration
}
