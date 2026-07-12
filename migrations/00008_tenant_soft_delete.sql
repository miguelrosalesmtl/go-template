-- +goose Up

-- Soft-delete for tenants. Deleting a tenant is the single most destructive act
-- in the product -- it takes every member's access and all their data with it --
-- so it must be undoable.
--
-- Semantics: setting deleted_at makes the tenant 404 for EVERYONE at once,
-- including its owners, and it vanishes from "my tenants". Not one row is
-- destroyed, so a superuser can restore it whole.
ALTER TABLE tenants ADD COLUMN deleted_at timestamptz;

-- Deleting a tenant releases its slug for anyone else to claim.
--
-- The old UNIQUE(slug) constraint would have held the slug hostage forever. A
-- partial unique index over the live tenants only lets "acme" be taken again once
-- the original is deleted.
--
-- THE COST, and it is a real one: restoring a tenant whose slug has since been
-- claimed by somebody else is impossible under this index -- there is no room for
-- two live "acme"s. Service.RestoreTenant therefore lets the superuser supply a
-- new slug. Restore stays possible; it cannot always give you your old URL back.
ALTER TABLE tenants DROP CONSTRAINT tenants_slug_key;
CREATE UNIQUE INDEX tenants_live_slug_idx ON tenants (slug) WHERE deleted_at IS NULL;

-- Nearly every query wants only live tenants, and this index is what keeps that
-- filter cheap.
CREATE INDEX tenants_deleted_at_idx ON tenants (deleted_at) WHERE deleted_at IS NULL;

-- +goose Down

DROP INDEX tenants_deleted_at_idx;
DROP INDEX tenants_live_slug_idx;

-- Restoring the plain UNIQUE constraint requires that no two tenants share a
-- slug, which soft-deletion may well have allowed. Purge the deleted ones: they
-- were unreachable anyway, and the old schema has no way to represent them.
DELETE FROM tenants WHERE deleted_at IS NOT NULL;

ALTER TABLE tenants ADD CONSTRAINT tenants_slug_key UNIQUE (slug);
ALTER TABLE tenants DROP COLUMN deleted_at;
