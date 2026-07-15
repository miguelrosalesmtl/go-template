-- Squashed baseline: the schema and seed data produced by the original
-- migrations 00001-00011, captured with pg_dump. The annotated, incremental
-- history is preserved in git before this commit.

-- +goose Up
--
-- PostgreSQL database dump
--


-- Dumped from database version 18.4
-- Dumped by pg_dump version 18.4


--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- Name: audit_log_is_append_only(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.audit_log_is_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Exactly ONE update is permitted, and it is not really a content change:
        -- audit_log.actor_user_id is ON DELETE SET NULL, so hard-deleting a user
        -- anonymises their entries rather than destroying them. That is deliberate,
        -- and it is how a right-to-erasure request is served without losing the
        -- record that the actions happened at all.
        --
        -- A blanket "no UPDATE" would make deleting a user impossible forever. So
        -- allow the anonymisation, and ONLY the anonymisation: every other column
        -- must be byte-for-byte identical, and actor_user_id may only go from set
        -- to NULL -- never the reverse, and never to somebody else.
        IF OLD.actor_user_id IS NOT NULL
           AND NEW.actor_user_id IS NULL
           AND NEW.id          =              OLD.id
           AND NEW.organization_id   IS NOT DISTINCT FROM OLD.organization_id
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
    --   * a hard delete of an organization, which cascades into its entries.
    --
    -- Note the consequence, and it is intended: hard-deleting an organization takes its
    -- audit trail with it. The APPLICATION never does this -- it soft-deletes,
    -- which destroys nothing. A hard delete is an out-of-band act and has to look
    -- like one.
    --
    -- AND NOTE THE LIMIT: any role can set this GUC. This stops an ACCIDENT, not an
    -- ADVERSARY -- code already running as the app can set it and delete. Real
    -- tamper-resistance needs a second, restricted DB identity; see internal/audit.
    IF TG_OP = 'DELETE'
       AND coalesce(current_setting('app.audit_purge', true), 'off') <> 'on' THEN
        RAISE EXCEPTION 'audit_log is append-only: rows cannot be deleted except by the retention sweep'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN OLD; -- permit the DELETE
END;
$$;
-- +goose StatementEnd


--
-- Name: audit_log_no_truncate(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.audit_log_no_truncate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: it cannot be truncated'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
-- +goose StatementEnd




--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid DEFAULT uuidv7() NOT NULL,
    organization_id uuid,
    actor_user_id uuid,
    action text NOT NULL,
    target_type text DEFAULT ''::text NOT NULL,
    target_id text DEFAULT ''::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    request_id text DEFAULT ''::text NOT NULL,
    ip_address inet,
    user_agent text DEFAULT ''::text NOT NULL
);


--
-- Name: email_verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_verifications (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    email public.citext NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.invitations (
    id uuid DEFAULT uuidv7() NOT NULL,
    organization_id uuid NOT NULL,
    email public.citext NOT NULL,
    token_hash bytea NOT NULL,
    invited_by uuid,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    role_id uuid NOT NULL
);


--
-- Name: membership_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.membership_roles (
    membership_id uuid NOT NULL,
    role_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.memberships (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id uuid DEFAULT uuidv7() NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: password_resets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_resets (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ip_address inet,
    user_agent text DEFAULT ''::text NOT NULL
);


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    key text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
    role_id uuid NOT NULL,
    permission text NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id uuid DEFAULT uuidv7() NOT NULL,
    organization_id uuid,
    key text NOT NULL,
    name text NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT roles_system_has_no_organization CHECK (((is_system AND (organization_id IS NULL)) OR ((NOT is_system) AND (organization_id IS NOT NULL))))
);


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    user_agent text DEFAULT ''::text NOT NULL,
    ip_address inet,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT uuidv7() NOT NULL,
    email public.citext NOT NULL,
    password_hash text,
    full_name text DEFAULT ''::text NOT NULL,
    is_superuser boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    email_verified_at timestamp with time zone
);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: email_verifications email_verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verifications
    ADD CONSTRAINT email_verifications_pkey PRIMARY KEY (id);


--
-- Name: email_verifications email_verifications_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verifications
    ADD CONSTRAINT email_verifications_token_hash_key UNIQUE (token_hash);


--
-- Name: invitations invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);


--
-- Name: invitations invitations_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_token_hash_key UNIQUE (token_hash);


--
-- Name: membership_roles membership_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_roles
    ADD CONSTRAINT membership_roles_pkey PRIMARY KEY (membership_id, role_id);


--
-- Name: memberships memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_pkey PRIMARY KEY (id);


--
-- Name: memberships memberships_user_id_organization_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_user_id_organization_id_key UNIQUE (user_id, organization_id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: password_resets password_resets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_resets
    ADD CONSTRAINT password_resets_pkey PRIMARY KEY (id);


--
-- Name: password_resets password_resets_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_resets
    ADD CONSTRAINT password_resets_token_hash_key UNIQUE (token_hash);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (key);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: audit_log_global_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_global_idx ON public.audit_log USING btree (id DESC) WHERE (organization_id IS NULL);


--
-- Name: audit_log_organization_action_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_organization_action_idx ON public.audit_log USING btree (organization_id, action, id DESC);


--
-- Name: audit_log_organization_actor_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_organization_actor_idx ON public.audit_log USING btree (organization_id, actor_user_id, id DESC);


--
-- Name: audit_log_organization_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_organization_id_idx ON public.audit_log USING btree (organization_id, id DESC);


--
-- Name: email_verifications_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_verifications_expires_at_idx ON public.email_verifications USING btree (expires_at);


--
-- Name: email_verifications_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_verifications_user_id_idx ON public.email_verifications USING btree (user_id);


--
-- Name: invitations_organization_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_organization_id_idx ON public.invitations USING btree (organization_id);


--
-- Name: invitations_pending_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX invitations_pending_email_idx ON public.invitations USING btree (organization_id, email) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL));


--
-- Name: membership_roles_role_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX membership_roles_role_id_idx ON public.membership_roles USING btree (role_id);


--
-- Name: memberships_organization_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX memberships_organization_id_idx ON public.memberships USING btree (organization_id);


--
-- Name: organizations_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_deleted_at_idx ON public.organizations USING btree (deleted_at) WHERE (deleted_at IS NULL);


--
-- Name: organizations_live_slug_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX organizations_live_slug_idx ON public.organizations USING btree (slug) WHERE (deleted_at IS NULL);


--
-- Name: password_resets_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX password_resets_expires_at_idx ON public.password_resets USING btree (expires_at);


--
-- Name: password_resets_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX password_resets_user_id_idx ON public.password_resets USING btree (user_id);


--
-- Name: roles_organization_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX roles_organization_key_idx ON public.roles USING btree (organization_id, key) WHERE (organization_id IS NOT NULL);


--
-- Name: roles_system_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX roles_system_key_idx ON public.roles USING btree (key) WHERE (organization_id IS NULL);


--
-- Name: sessions_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_expires_at_idx ON public.sessions USING btree (expires_at);


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_id_idx ON public.sessions USING btree (user_id);


--
-- Name: audit_log audit_log_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_log_append_only BEFORE DELETE OR UPDATE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.audit_log_is_append_only();


--
-- Name: audit_log audit_log_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON public.audit_log FOR EACH STATEMENT EXECUTE FUNCTION public.audit_log_no_truncate();


--
-- Name: audit_log audit_log_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: audit_log audit_log_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: email_verifications email_verifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verifications
    ADD CONSTRAINT email_verifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: invitations invitations_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: invitations invitations_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: invitations invitations_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: membership_roles membership_roles_membership_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_roles
    ADD CONSTRAINT membership_roles_membership_id_fkey FOREIGN KEY (membership_id) REFERENCES public.memberships(id) ON DELETE CASCADE;


--
-- Name: membership_roles membership_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_roles
    ADD CONSTRAINT membership_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE RESTRICT;


--
-- Name: memberships memberships_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: memberships memberships_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: password_resets password_resets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_resets
    ADD CONSTRAINT password_resets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_permission_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_fkey FOREIGN KEY (permission) REFERENCES public.permissions(key) ON DELETE RESTRICT;


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: roles roles_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--



-- Seed data: the permission catalog, the three immutable system roles
-- (owner/admin/member), and their permission grants.
INSERT INTO public.permissions VALUES ('organization.read', 'View the organization and its settings', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.permissions VALUES ('organization.update', 'Change the organization''s name and settings', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.permissions VALUES ('organization.delete', 'Delete the organization entirely', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.permissions VALUES ('members.read', 'View the organization''s members', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.permissions VALUES ('roles.read', 'View the organization''s roles', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.permissions VALUES ('audit.read', 'Read the organization''s audit log', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.permissions VALUES ('invitations.read', 'View pending invitations', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.permissions VALUES ('invitations.create', 'Invite people to the organization', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.permissions VALUES ('invitations.delete', 'Revoke a pending invitation', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.permissions VALUES ('members.update', 'Change which roles a member holds', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.permissions VALUES ('members.delete', 'Remove members from the organization', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.permissions VALUES ('roles.create', 'Create custom roles', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.permissions VALUES ('roles.update', 'Edit custom roles', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.permissions VALUES ('roles.delete', 'Delete custom roles', '2026-07-15 00:09:52.114943+00');
INSERT INTO public.roles VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', NULL, 'owner', 'Owner', true, '2026-07-15 00:09:52.103097+00', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.roles VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', NULL, 'admin', 'Admin', true, '2026-07-15 00:09:52.103097+00', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.roles VALUES ('019f631b-c4ef-7225-a428-689600b42bc8', NULL, 'member', 'Member', true, '2026-07-15 00:09:52.103097+00', '2026-07-15 00:09:52.103097+00');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'organization.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'organization.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'organization.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'members.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'roles.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'audit.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'organization.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'organization.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'members.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'audit.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7225-a428-689600b42bc8', 'organization.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7225-a428-689600b42bc8', 'members.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'invitations.create');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'invitations.create');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'members.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'members.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'members.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'members.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'roles.create');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'roles.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'roles.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.create');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'invitations.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-70f1-b9d6-de3c13e92074', 'invitations.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'invitations.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'invitations.delete');

-- +goose Down
DROP TABLE IF EXISTS public.audit_log, public.email_verifications, public.invitations, public.membership_roles, public.memberships, public.organizations, public.password_resets, public.role_permissions, public.roles, public.sessions, public.users, public.permissions CASCADE;
DROP FUNCTION IF EXISTS public.audit_log_is_append_only() CASCADE;
DROP FUNCTION IF EXISTS public.audit_log_no_truncate() CASCADE;
DROP EXTENSION IF EXISTS citext;
