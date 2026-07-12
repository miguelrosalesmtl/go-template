-- +goose Up
-- citext gives us case-insensitive emails without lower() on every lookup.
-- uuidv7() is built into Postgres 18+, so no extension is needed for UUIDs.
-- v7 is time-ordered, which keeps primary-key index inserts sequential.
CREATE EXTENSION IF NOT EXISTS citext;

-- +goose Down
DROP EXTENSION IF EXISTS citext;
