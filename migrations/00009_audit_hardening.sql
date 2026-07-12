-- +goose Up

-- Turn the audit log from a change-history into an audit trail. Three things.

-- 1. WHO, FROM WHERE, AND IN WHICH REQUEST.
--
-- The log recorded what happened and who did it, but not the request it came in
-- on -- so an entry could never be tied back to the application logs for that
-- request, which is the first thing anyone wants during an incident.
ALTER TABLE audit_log ADD COLUMN request_id text NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN ip_address inet;
ALTER TABLE audit_log ADD COLUMN user_agent text NOT NULL DEFAULT '';

-- 2. SEARCH.
--
-- Pagination alone is useless at 100k rows: "did anyone touch roles last March"
-- is not a question you can answer by scrolling. These serve the filters on
-- GET /audit.
CREATE INDEX audit_log_tenant_action_idx ON audit_log (tenant_id, action, id DESC);
CREATE INDEX audit_log_tenant_actor_idx  ON audit_log (tenant_id, actor_user_id, id DESC);

-- Denials are recorded with no tenant when there is none to record (a failed
-- login has not identified a tenant yet). This index is what makes them findable.
CREATE INDEX audit_log_global_idx ON audit_log (id DESC) WHERE tenant_id IS NULL;

-- 3. APPEND-ONLY -- AND BE CLEAR ABOUT WHAT THAT DOES AND DOES NOT BUY YOU.
--
-- The trigger below refuses UPDATE, DELETE, and TRUNCATE on audit_log. It catches:
--
--     * a bug, an ORM, or a future migration that deletes rows by accident
--     * an injected `DELETE FROM audit_log` from a SQL-injection flaw
--     * anybody who simply did not know the table was meant to be append-only
--
-- IT DOES NOT MAKE THE AUDIT LOG TAMPER-PROOF AGAINST A COMPROMISED APPLICATION,
-- and it would be dishonest to imply otherwise. The DELETE branch permits the
-- retention sweep, which identifies itself by setting a GUC -- and ANY role can set
-- that GUC. No special privilege is required. So code that is already executing as
-- the application can set it and delete whatever it likes:
--
--     BEGIN;
--     SET LOCAL app.audit_purge = 'on';
--     DELETE FROM audit_log;      -- succeeds
--     COMMIT;
--
-- Making that impossible requires TWO database identities: one that may destroy
-- history, and a different, restricted one that the application actually connects
-- as, holding no DELETE on this table. That is a real design and it is not the one
-- this template uses -- we run a single user that owns the database, for
-- operational simplicity, and accept the consequence.
--
-- So: this trigger is a guard against MISTAKES, not against an ADVERSARY who
-- already owns your process. Size your expectations accordingly.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Exactly ONE update is permitted, and it is not really a content change:
        -- audit_log.actor_user_id is ON DELETE SET NULL, so hard-deleting a user
        -- anonymises their entries rather than destroying them. That is deliberate
        -- (see 00005) and it is how a right-to-erasure request is served without
        -- losing the record that the actions happened at all.
        --
        -- A blanket "no UPDATE" would make deleting a user impossible forever. So
        -- allow the anonymisation, and ONLY the anonymisation: every other column
        -- must be byte-for-byte identical, and actor_user_id may only go from set
        -- to NULL -- never the reverse, and never to somebody else.
        IF OLD.actor_user_id IS NOT NULL
           AND NEW.actor_user_id IS NULL
           AND NEW.id          =              OLD.id
           AND NEW.tenant_id   IS NOT DISTINCT FROM OLD.tenant_id
           AND NEW.action      =              OLD.action
           AND NEW.target_type =              OLD.target_type
           AND NEW.target_id   =              OLD.target_id
           AND NEW.metadata    =              OLD.metadata
           AND NEW.request_id  =              OLD.request_id
           AND NEW.ip_address  IS NOT DISTINCT FROM OLD.ip_address
           AND NEW.user_agent  =              OLD.user_agent
           AND NEW.created_at  =              OLD.created_at
        THEN
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'audit_log is append-only: rows cannot be modified'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- DELETE is allowed only to deliberate audit maintenance, which announces
    -- itself by setting this GUC for the duration of its transaction:
    --
    --   * the retention sweep (`server purge`), and
    --   * a hard delete of a tenant, which cascades into its entries.
    --
    -- Note the consequence, and it is intended: hard-deleting a tenant takes its
    -- audit trail with it. The APPLICATION never does this -- it soft-deletes,
    -- which destroys nothing. A hard delete is an out-of-band act and has to look
    -- like one.
    --
    -- AND NOTE THE LIMIT: any role can set this GUC. This stops an ACCIDENT, not an
    -- ADVERSARY. See the long comment at the top of this file.
    IF TG_OP = 'DELETE'
       AND coalesce(current_setting('app.audit_purge', true), 'off') <> 'on' THEN
        RAISE EXCEPTION 'audit_log is append-only: rows cannot be deleted except by the retention sweep'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN OLD; -- permit the DELETE
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_is_append_only();

-- And TRUNCATE, which would otherwise walk straight past the trigger above.
--
-- TRUNCATE does not fire row-level triggers -- it is not a DELETE, it discards the
-- whole heap -- so without this, `TRUNCATE audit_log` erases the entire history in
-- one statement while every protection above looks on. It needs its own
-- STATEMENT-level trigger.
--
-- This is the sort of gap that makes "append-only by convention" worthless: the
-- convention holds until somebody finds the one verb nobody thought about.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_log_no_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: it cannot be truncated'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_no_truncate();

-- +goose Down

DROP TRIGGER audit_log_no_truncate ON audit_log;
DROP FUNCTION audit_log_no_truncate();
DROP TRIGGER audit_log_append_only ON audit_log;
DROP FUNCTION audit_log_is_append_only();

DROP INDEX audit_log_global_idx;
DROP INDEX audit_log_tenant_actor_idx;
DROP INDEX audit_log_tenant_action_idx;

ALTER TABLE audit_log DROP COLUMN user_agent;
ALTER TABLE audit_log DROP COLUMN ip_address;
ALTER TABLE audit_log DROP COLUMN request_id;
