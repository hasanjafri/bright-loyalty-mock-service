DROP TABLE IF EXISTS admin;

DROP TABLE IF EXISTS vendor;

DROP TABLE IF EXISTS customer;

CREATE TABLE admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    primary_color TEXT NOT NULL,
    secondary_color TEXT NOT NULL,
    accent TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vendor (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    primary_color TEXT NOT NULL,
    secondary_color TEXT NOT NULL,
    accent TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE customer (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    vendor_id INTEGER NOT NULL,
    primary_color TEXT NOT NULL,
    secondary_color TEXT NOT NULL,
    accent TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES vendor (id)
);