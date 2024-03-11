CREATE TABLE users
(
    subject        TEXT PRIMARY KEY UNIQUE     NOT NULL,
    name           TEXT                        NOT NULL,
    username       TEXT UNIQUE                 NOT NULL,
    password       TEXT                        NOT NULL,
    picture        TEXT    DEFAULT ''          NOT NULL,
    website        TEXT    DEFAULT ''          NOT NULL,
    email          TEXT                        NOT NULL,
    email_verified BOOLEAN DEFAULT 0           NOT NULL,
    pronouns       TEXT    DEFAULT 'they/them' NOT NULL,
    birthdate      DATE,
    zoneinfo       TEXT    DEFAULT 'UTC'       NOT NULL,
    locale         TEXT    DEFAULT 'en-US'     NOT NULL,
    role           INTEGER DEFAULT 0           NOT NULL,
    updated_at     DATETIME                    NOT NULL,
    registered     DATETIME                    NOT NULL,
    active         BOOLEAN DEFAULT 1           NOT NULL
);

CREATE UNIQUE INDEX username_index ON users (username);

CREATE TABLE client_store
(
    subject TEXT PRIMARY KEY UNIQUE NOT NULL,
    name    TEXT                    NOT NULL,
    secret  TEXT UNIQUE             NOT NULL,
    domain  TEXT                    NOT NULL,
    owner   TEXT                    NOT NULL,
    public  BOOLEAN                 NOT NULL,
    sso     BOOLEAN                 NOT NULL,
    active  BOOLEAN DEFAULT 1       NOT NULL,
    FOREIGN KEY (owner) REFERENCES users (subject)
);

CREATE TABLE otp
(
    subject TEXT PRIMARY KEY UNIQUE NOT NULL,
    secret  TEXT                    NOT NULL,
    digits  INTEGER                 NOT NULL,
    FOREIGN KEY (subject) REFERENCES users (subject)
);
