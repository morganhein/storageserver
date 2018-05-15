package datastore

import (
	"github.com/hashicorp/go-memdb"
)

type User struct {
	Username string
	Password string
}

type Session struct {
	Token    string
	Username string
}

type File struct {
	Filename    string
	Username    string //fk
	Data        []byte
	ContentType string
}

var DB *memdb.MemDB

var schema *memdb.DBSchema = &memdb.DBSchema{
	Tables: map[string]*memdb.TableSchema{
		"users": &memdb.TableSchema{
			Name: "users",
			Indexes: map[string]*memdb.IndexSchema{
				"id": &memdb.IndexSchema{
					Name:    "id",
					Unique:  true,
					Indexer: &memdb.StringFieldIndex{Field: "Username"},
				},
			},
		},
		"sessions": &memdb.TableSchema{
			Name: "sessions",
			Indexes: map[string]*memdb.IndexSchema{
				"id": &memdb.IndexSchema{
					Name:    "id",
					Unique:  true,
					Indexer: &memdb.StringFieldIndex{Field: "Token"},
				},
			},
		},
		"files": &memdb.TableSchema{
			Name: "files",
			Indexes: map[string]*memdb.IndexSchema{
				"id": &memdb.IndexSchema{
					Name:   "id",
					Unique: true,
					Indexer: &memdb.CompoundIndex{
						Indexes: []memdb.Indexer{
							&memdb.StringFieldIndex{Field: "Filename"},
							&memdb.StringFieldIndex{Field: "Username"},
						},
					},
				},
				"user": &memdb.IndexSchema{
					Name:    "user",
					Unique:  true,
					Indexer: &memdb.StringFieldIndex{Field: "Username"},
				},
			},
		},
	},
}

//MakeDB creates a new in-memory database useful for a simple storage server
func MakeDB() error {
	memdb.NewMemDB(schema)
	var err error
	DB, err = memdb.NewMemDB(schema)
	return err
}
