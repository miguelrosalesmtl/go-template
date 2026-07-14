-- +goose Up

-- Soft-delete for organizations. Deleting an organization is the single most destructive act
-- in the product -- it takes every member's access and all their data with it --
-- so it must be undoable.
--
-- Semantics: setting deleted_at makes the organization 404 for EVERYONE at once,
-- including its owners, and it vanishes from "my organizations". Not one row is
-- destroyed, so a superuser can restore it whole.
ALTER TABLE organizations ADD COLUMN deleted_at timestamptz;

-- Deleting an organization releases its slug for anyone else to claim.
--
-- The old UNIQUE(slug) constraint would have held the slug hostage forever. A
-- partial unique index over the live organizations only lets "acme" be taken again once
-- the original is deleted.
--
-- THE COST, and it is a real one: restoring an organization whose slug has since been
-- claimed by somebody else is impossible under this index -- there is no room for
-- two live "acme"s. Service.RestoreOrganization therefore lets the superuser supply a
-- new slug. Restore stays possible; it cannot always give you your old URL back.
ALTER TABLE organizations DROP CONSTRAINT organizations_slug_key;
CREATE UNIQUE INDEX organizations_live_slug_idx ON organizations (slug) WHERE deleted_at IS NULL;

-- Nearly every query wants only live organizations, and this index is what keeps that
-- filter cheap.
CREATE INDEX organizations_deleted_at_idx ON organizations (deleted_at) WHERE deleted_at IS NULL;

-- +goose Down

DROP INDEX organizations_deleted_at_idx;
DROP INDEX organizations_live_slug_idx;

-- Restoring the plain UNIQUE constraint requires that no two organizations share a
-- slug, which soft-deletion may well have allowed. Purge the deleted ones: they
-- were unreachable anyway, and the old schema has no way to represent them.
DELETE FROM organizations WHERE deleted_at IS NOT NULL;

ALTER TABLE organizations ADD CONSTRAINT organizations_slug_key UNIQUE (slug);
ALTER TABLE organizations DROP COLUMN deleted_at;
