/* Gorilla Sessions backend for sqlite + in memory database.

Copyright (c) 2018 Contributors. See the list of contributors in the CONTRIBUTORS file for details.

This software is licensed under a MIT style license available in the LICENSE file.
*/
package sqlitestore

import (
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/mattn/go-sqlite3"
	"path/filepath"
	"os"
)

type SqliteStore struct {
	db         DB
	stmtInsert *sql.Stmt
	stmtDelete *sql.Stmt
	stmtUpdate *sql.Stmt
	stmtSelect *sql.Stmt

	filedb        DB
	stmtInsertFDB *sql.Stmt
	stmtDeleteFDB *sql.Stmt
	stmtUpdateFDB *sql.Stmt

	Codecs  []securecookie.Codec
	Options *sessions.Options
	table   string
}

type sessionRow struct {
	id         string
	data       string
	createdOn  time.Time
	modifiedOn time.Time
	expiresOn  time.Time
}

type DB interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Prepare(query string) (*sql.Stmt, error)
	Close() error
}

const (
	driverName = "sqlite3_sync_sqlite_storage"
)

func init() {
	gob.Register(time.Time{})
}

func NewStore(endpoint string, tableName string, path string, maxAge int, keyPairs ...[]byte) (*SqliteStore, error) {
	// Init memory & file db
	var conns = []*sqlite3.SQLiteConn{}

	sql.Register(driverName, &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			conns = append(conns, conn)
			return nil
		},
	})

	os.MkdirAll(filepath.Dir(endpoint), 0755)

	db, err := sql.Open(driverName, ":memory:")
	if err != nil {
		return nil, err
	}
	db.Ping()
	filedb, err := sql.Open(driverName, endpoint)
	if err != nil {
		return nil, err
	}
	filedb.Ping()
	if len(conns) != 2 {
		return nil, errors.New(fmt.Sprintf("Expected 2 driver connections, but found ", len(conns)))

	}
	backup, err := conns[0].Backup("main", conns[1], "main")
	if _, err = backup.Step(-1); err != nil {
		return nil, err
	}
	if err = backup.Finish(); err != nil {
		return nil, err
	}

	return NewSqliteStoreFromConnection(db, filedb, tableName, path, maxAge, keyPairs...)
}

func NewSqliteStoreFromConnection(db DB, filedb DB, tableName string, path string, maxAge int, keyPairs ...[]byte) (*SqliteStore, error) {
	// Make sure table name is enclosed.
	tableName = "`" + strings.Trim(tableName, "`") + "`"

	cTableQ := "CREATE TABLE IF NOT EXISTS " +
		tableName + " (id INTEGER PRIMARY KEY, " +
		"session_data LONGBLOB, " +
		"created_on TIMESTAMP DEFAULT 0, " +
		"modified_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
		"expires_on TIMESTAMP DEFAULT 0);"
	if _, err := db.Exec(cTableQ); err != nil {
		return nil, err
	}
	if _, err := filedb.Exec(cTableQ); err != nil {
		return nil, err
	}

	insQ := "INSERT INTO " + tableName +
		"(id, session_data, created_on, modified_on, expires_on) VALUES (NULL, ?, ?, ?, ?)"
	stmtInsert, stmtErr := db.Prepare(insQ)
	if stmtErr != nil {
		return nil, stmtErr
	}
	stmtInsertFDB, stmtErr := db.Prepare(insQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	delQ := "DELETE FROM " + tableName + " WHERE id = ?"
	stmtDelete, stmtErr := db.Prepare(delQ)
	if stmtErr != nil {
		return nil, stmtErr
	}
	stmtDeleteFDB, stmtErr := db.Prepare(delQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	updQ := "UPDATE " + tableName + " SET session_data = ?, created_on = ?, expires_on = ? " +
		"WHERE id = ?"
	stmtUpdate, stmtErr := db.Prepare(updQ)
	if stmtErr != nil {
		return nil, stmtErr
	}
	stmtUpdateFDB, stmtErr := db.Prepare(updQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	selQ := "SELECT id, session_data, created_on, modified_on, expires_on from " +
		tableName + " WHERE id = ?"
	stmtSelect, stmtErr := db.Prepare(selQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	return &SqliteStore{
		db:            db,
		stmtInsert:    stmtInsert,
		stmtDelete:    stmtDelete,
		stmtUpdate:    stmtUpdate,
		stmtSelect:    stmtSelect,
		filedb:        db,
		stmtInsertFDB: stmtInsertFDB,
		stmtDeleteFDB: stmtDeleteFDB,
		stmtUpdateFDB: stmtUpdateFDB,
		Codecs:        securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   path,
			MaxAge: maxAge,
		},
		table: tableName,
	}, nil
}

func (m *SqliteStore) Close() {
	m.stmtSelect.Close()
	m.stmtUpdate.Close()
	m.stmtDelete.Close()
	m.stmtInsert.Close()
	m.db.Close()
	m.stmtUpdateFDB.Close()
	m.stmtDeleteFDB.Close()
	m.stmtInsertFDB.Close()
	m.db.Close()
}

func (m *SqliteStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

func (m *SqliteStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:   m.Options.Path,
		MaxAge: m.Options.MaxAge,
	}
	session.IsNew = true
	var err error
	if cook, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cook.Value, &session.ID, m.Codecs...)
		if err == nil {
			err = m.load(session)
			if err == nil {
				session.IsNew = false
			} else {
				err = nil
			}
		}
	}
	return session, err
}

func (m *SqliteStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	var err error
	if session.ID == "" {
		if err = m.insert(session); err != nil {
			return err
		}
	} else if err = m.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, m.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (m *SqliteStore) insert(session *sessions.Session) error {
	var createdOn time.Time
	var modifiedOn time.Time
	var expiresOn time.Time
	crOn := session.Values["created_on"]
	if crOn == nil {
		createdOn = time.Now()
	} else {
		createdOn = crOn.(time.Time)
	}
	modifiedOn = createdOn
	exOn := session.Values["expires_on"]
	if exOn == nil {
		expiresOn = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresOn = exOn.(time.Time)
	}
	delete(session.Values, "created_on")
	delete(session.Values, "expires_on")
	delete(session.Values, "modified_on")

	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, m.Codecs...)
	if encErr != nil {
		return encErr
	}
	//filedb insert
	_, insErr := m.stmtInsertFDB.Exec(encoded, createdOn, modifiedOn, expiresOn)
	if insErr != nil {
		return insErr
	}
	res, insErr := m.stmtInsert.Exec(encoded, createdOn, modifiedOn, expiresOn)
	if insErr != nil {
		return insErr
	}
	lastInserted, lInsErr := res.LastInsertId()
	if lInsErr != nil {
		return lInsErr
	}
	session.ID = fmt.Sprintf("%d", lastInserted)
	return nil
}

func (m *SqliteStore) Delete(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {

	// Set cookie to expire.
	options := *session.Options
	options.MaxAge = -1
	http.SetCookie(w, sessions.NewCookie(session.Name(), "", &options))
	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}
	// filedb delete
	_, delErr := m.stmtDeleteFDB.Exec(session.ID)
	if delErr != nil {
		return delErr
	}
	_, delErr = m.stmtDelete.Exec(session.ID)
	if delErr != nil {
		return delErr
	}
	return nil
}

func (m *SqliteStore) save(session *sessions.Session) error {
	if session.IsNew == true {
		return m.insert(session)
	}
	var createdOn time.Time
	var expiresOn time.Time
	crOn := session.Values["created_on"]
	if crOn == nil {
		createdOn = time.Now()
	} else {
		createdOn = crOn.(time.Time)
	}

	exOn := session.Values["expires_on"]
	if exOn == nil {
		expiresOn = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
		log.Print("nil")
	} else {
		expiresOn = exOn.(time.Time)
		if expiresOn.Sub(time.Now().Add(time.Second*time.Duration(session.Options.MaxAge))) < 0 {
			expiresOn = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
		}
	}

	delete(session.Values, "created_on")
	delete(session.Values, "expires_on")
	delete(session.Values, "modified_on")
	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, m.Codecs...)
	if encErr != nil {
		return encErr
	}
	// filedb update
	_, updErr := m.stmtUpdateFDB.Exec(encoded, createdOn, expiresOn, session.ID)
	if updErr != nil {
		return updErr
	}
	_, updErr = m.stmtUpdate.Exec(encoded, createdOn, expiresOn, session.ID)
	if updErr != nil {
		return updErr
	}
	return nil
}

func (m *SqliteStore) load(session *sessions.Session) error {
	row := m.stmtSelect.QueryRow(session.ID)
	sess := sessionRow{}
	scanErr := row.Scan(&sess.id, &sess.data, &sess.createdOn, &sess.modifiedOn, &sess.expiresOn)
	if scanErr != nil {
		return scanErr
	}
	if sess.expiresOn.Sub(time.Now()) < 0 {
		log.Printf("Session expired on %s, but it is %s now.", sess.expiresOn, time.Now())
		return errors.New("Session expired")
	}
	err := securecookie.DecodeMulti(session.Name(), sess.data, &session.Values, m.Codecs...)
	if err != nil {
		return err
	}
	session.Values["created_on"] = sess.createdOn
	session.Values["modified_on"] = sess.modifiedOn
	session.Values["expires_on"] = sess.expiresOn
	return nil
}
