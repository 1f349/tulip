package database

import (
	"github.com/1f349/tulip/password"
	"github.com/MrMelon54/pronouns"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	"testing"
	"time"
)

func TestTx_ChangeUserPassword(t *testing.T) {
	u := uuid.New()
	pw, err := password.HashPassword("test")
	assert.NoError(t, err)
	d, err := Open("file::memory:")
	assert.NoError(t, err)
	_, err = d.db.Exec(`INSERT INTO users (subject, name, username, password, email, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, u.String(), "Test", "test", pw, "test@localhost", updatedAt())
	assert.NoError(t, err)
	tx, err := d.Begin()
	assert.NoError(t, err)
	err = tx.ChangeUserPassword(u, "test", "new")
	assert.NoError(t, err)
	assert.NoError(t, tx.Commit())
	query, err := d.db.Query(`SELECT password FROM users WHERE subject = ? AND username = ?`, u.String(), "test")
	assert.NoError(t, err)
	assert.True(t, query.Next())
	var oldPw password.HashString
	assert.NoError(t, query.Scan(&oldPw))
	assert.NoError(t, password.CheckPasswordHash(oldPw, "new"))
	assert.NoError(t, query.Err())
	assert.NoError(t, query.Close())
}

func TestTx_ModifyUser(t *testing.T) {
	u := uuid.New()
	pw, err := password.HashPassword("test")
	assert.NoError(t, err)
	d, err := Open("file::memory:")
	assert.NoError(t, err)
	_, err = d.db.Exec(`INSERT INTO users (subject, name, username, password, email, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, u.String(), "Test", "test", pw, "test@localhost", updatedAt())
	assert.NoError(t, err)
	tx, err := d.Begin()
	assert.NoError(t, err)
	assert.NoError(t, tx.ModifyUser(u, &UserPatch{
		Name:     "example",
		Pronouns: pronouns.TheyThem,
		ZoneInfo: time.UTC,
		Locale:   language.AmericanEnglish,
	}))
}
