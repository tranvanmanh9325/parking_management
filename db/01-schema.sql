-- =============================================================================
-- FILE: db/01-schema.sql
-- PROJECT: Car Parking Lot Management System Backend (parking_management_backend)
-- TARGET ENGINE: PostgreSQL 18.6
-- DESCRIPTION:
--   Enterprise-grade relational database schema (Schema v2 — Frontend-First).
--   Primary source: Frontend export (`Parking Project`, 11 PNG screens) and
--   Team Lead Decisions TL-01 through TL-41.
--   Secondary source: SRS v4.1 (`Quan ly bai dau xe oto_SRS_v4.1.docx`) where
--   the Frontend is silent.
--   Strictly adheres to ADR-0003 (Soft Delete & ON DELETE RESTRICT), ADR-0004
--   (OWASP Persistent Login Token), and Rule 05 (PostgreSQL Data Modeling).
--   NOTE: Pure creation script. Zero destructive statements are permitted.
--   SCOPE (database-design stage): tables, constraints, indexes, comments and
--   analytical views only. Triggers and business-logic functions are removed
--   for this stage; only fn_normalize_license_plate remains because generated
--   columns depend on it.
-- =============================================================================

BEGIN;

SET client_encoding = 'UTF8';

-- Required for temporal exclusion constraints combining BIGINT with TSTZRANGE (TL-04, TL-10, TL-15)
CREATE EXTENSION btree_gist;

-- Required for partial GIN trigram indexes for fast substring search (TL-41, F6)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- =============================================================================
-- SECTION 0: CANONICAL NORMALIZATION FUNCTIONS (TL-05, TL-08, TL-15, OQ-75)
-- =============================================================================

CREATE FUNCTION fn_normalize_license_plate(p_input TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE STRICT PARALLEL SAFE
SET search_path = public, pg_temp
AS $$
    SELECT UPPER(REGEXP_REPLACE(p_input, '[^A-Za-z0-9]', '', 'g'));
$$;

COMMENT ON FUNCTION fn_normalize_license_plate(TEXT) IS 'Normalizes vehicle license plates by stripping non-alphanumeric separators (dots, hyphens, spaces) and converting to uppercase for canonical uniqueness and barrier matching (TL-05, TL-08, TL-15, OQ-75).';

-- =============================================================================
-- SECTION 1: AUTHENTICATION & ACCESS CONTROL MODULE (TL-01, TL-15, SRS 4.1)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1.1. Table: account
-- Source: Frontend `login-container.png` ("Email hoặc Số điện thoại", "Mật khẩu",
--         "Ghi nhớ đăng nhập", "Quên mật khẩu?", "Đăng ký ngay"), TL-01, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE account (
    id BIGSERIAL,
    email VARCHAR(100) NULL,
    phone VARCHAR(15) NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'EMPLOYEE',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_account PRIMARY KEY (id),
    CONSTRAINT fk_account_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_account_login_identifier_present CHECK (num_nonnulls(email, phone) >= 1),
    CONSTRAINT ck_account_email_format CHECK (
        email IS NULL OR (btrim(email) <> '' AND email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
    ),
    CONSTRAINT ck_account_phone_digits CHECK (
        phone IS NULL OR phone ~ '^[0-9]{9,15}$'
    ),
    CONSTRAINT ck_account_password_nonempty CHECK (btrim(password_hash) <> ''),
    CONSTRAINT ck_account_role_enum CHECK (role IN ('MANAGER', 'EMPLOYEE', 'CUSTOMER')),
    CONSTRAINT ck_account_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_account_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_account_email_active
    ON account (lower(email))
    WHERE deleted_at IS NULL AND email IS NOT NULL;

CREATE UNIQUE INDEX uq_account_phone_active
    ON account (phone)
    WHERE deleted_at IS NULL AND phone IS NOT NULL;

CREATE INDEX idx_account_role_active
    ON account (role)
    WHERE deleted_at IS NULL AND is_active = TRUE;

COMMENT ON TABLE account IS 'System authentication accounts using email or phone login identifiers and supporting self-registered customers (login-container.png, TL-01, TL-15).';
COMMENT ON COLUMN account.id IS 'Primary key identifier of the system account.';
COMMENT ON COLUMN account.email IS 'Login email address for authentication ("Email hoặc Số điện thoại" on login-container.png, TL-01); case-insensitively unique via lower(email) among active accounts when present (TL-21, OQ-84).';
COMMENT ON COLUMN account.phone IS 'Login phone number (9-15 digits) for authentication ("Email hoặc Số điện thoại" on login-container.png, TL-01); unique among active accounts when present.';
COMMENT ON COLUMN account.password_hash IS 'Cryptographic password hash (Argon2id/PBKDF2) for "Mật khẩu" on login-container.png (TL-01, ADR-0004).';
COMMENT ON COLUMN account.role IS 'Authorization role: MANAGER (Quản lý), EMPLOYEE (Nhân viên), or CUSTOMER (Khách hàng self-registration per TL-01, OQ-03, OQ-55).';
COMMENT ON COLUMN account.is_active IS 'Account activation status flag ("Khoá tài khoản" on Quản lý nhân viên, TL-01, TL-11).';
COMMENT ON COLUMN account.last_login_at IS 'Timestamp of the most recent successful authentication.';
COMMENT ON COLUMN account.row_version IS 'Optimistic concurrency control version counter incremented automatically on update (TL-15, OQ-64).';
COMMENT ON COLUMN account.created_at IS 'Record creation timestamp (TIMESTAMPTZ).';
COMMENT ON COLUMN account.updated_at IS 'Record last modification timestamp (TIMESTAMPTZ).';
COMMENT ON COLUMN account.deleted_at IS 'Soft deletion timestamp; NULL indicates active record (ADR-0003, TL-15).';
COMMENT ON COLUMN account.deleted_by IS 'Foreign key referencing the account that performed soft deletion (ADR-0003, TL-15).';

-- -----------------------------------------------------------------------------
-- 1.2. Table: persistent_login_token
-- Source: Frontend `login-container.png` ("Ghi nhớ đăng nhập"), TL-01, TL-15, ADR-0004
-- -----------------------------------------------------------------------------
CREATE TABLE persistent_login_token (
    id BIGSERIAL,
    series VARCHAR(64) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    account_id BIGINT NOT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_persistent_login_token PRIMARY KEY (id),
    CONSTRAINT uq_persistent_login_token_series UNIQUE (series),
    CONSTRAINT fk_plt_account FOREIGN KEY (account_id)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_plt_series_nonempty CHECK (btrim(series) <> ''),
    CONSTRAINT ck_plt_token_nonempty CHECK (btrim(token_hash) <> ''),
    CONSTRAINT ck_plt_expiry_order CHECK (expires_at > created_at)
);

CREATE INDEX idx_plt_account_id ON persistent_login_token (account_id);
CREATE INDEX idx_plt_expires_at ON persistent_login_token (expires_at);

COMMENT ON TABLE persistent_login_token IS 'OWASP Series/Token persistent login store for "Ghi nhớ đăng nhập" (login-container.png, TL-01, TL-15, ADR-0004, OQ-01).';
COMMENT ON COLUMN persistent_login_token.id IS 'Primary key identifier of the persistent login token.';
COMMENT ON COLUMN persistent_login_token.series IS 'Unique token series identifier for theft detection across rotations.';
COMMENT ON COLUMN persistent_login_token.token_hash IS 'SHA-256 cryptographic hash of the rotating single-use remember-me token.';
COMMENT ON COLUMN persistent_login_token.account_id IS 'Foreign key referencing the authenticated account.';
COMMENT ON COLUMN persistent_login_token.ip_address IS 'Client IPv4/IPv6 address recorded at session issuance.';
COMMENT ON COLUMN persistent_login_token.user_agent IS 'Client browser User-Agent string recorded at session issuance.';
COMMENT ON COLUMN persistent_login_token.created_at IS 'Timestamp when the persistent session was initially established.';
COMMENT ON COLUMN persistent_login_token.last_used_at IS 'Timestamp when the token was most recently rotated.';
COMMENT ON COLUMN persistent_login_token.expires_at IS 'Expiration timestamp after which the persistent token is invalid.';

-- -----------------------------------------------------------------------------
-- 1.3. Table: password_reset_token
-- Source: Frontend `login-container.png` ("Quên mật khẩu?") & `Quản lý nhân viên` ("Đặt lại mật khẩu"), TL-01, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE password_reset_token (
    id BIGSERIAL,
    account_id BIGINT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    requested_ip VARCHAR(45) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_password_reset_token PRIMARY KEY (id),
    CONSTRAINT uq_password_reset_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_prt_account FOREIGN KEY (account_id)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_prt_token_nonempty CHECK (btrim(token_hash) <> ''),
    CONSTRAINT ck_prt_expiry_order CHECK (expires_at > created_at)
);

CREATE INDEX idx_prt_account_id ON password_reset_token (account_id);

COMMENT ON TABLE password_reset_token IS 'Single-use cryptographic token store for "Quên mật khẩu?" and "Đặt lại mật khẩu" (login-container.png, TL-01, TL-15, SCO-05).';
COMMENT ON COLUMN password_reset_token.id IS 'Primary key identifier of the password reset token.';
COMMENT ON COLUMN password_reset_token.account_id IS 'Foreign key referencing the account requesting password recovery.';
COMMENT ON COLUMN password_reset_token.token_hash IS 'Cryptographic hash of the one-time reset token.';
COMMENT ON COLUMN password_reset_token.expires_at IS 'Token expiration timestamp.';
COMMENT ON COLUMN password_reset_token.used_at IS 'Timestamp when the token was consumed; NULL if unused.';
COMMENT ON COLUMN password_reset_token.requested_ip IS 'Requester IPv4/IPv6 address for security auditing.';
COMMENT ON COLUMN password_reset_token.created_at IS 'Token generation timestamp.';

-- =============================================================================
-- SECTION 2: HUMAN RESOURCES & ADMINISTRATIVE GEOGRAPHY (TL-11, TL-15, SRS 4.3)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 2.1. Table: position
-- Source: Frontend `Quản lý nhân viên - Smart mobility.png` ("Chức vụ: 4" — Quản lý, Nhân viên vận hành, Nhân viên thu ngân, Kỹ thuật viên), TL-11
-- -----------------------------------------------------------------------------
CREATE TABLE position (
    id BIGSERIAL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(50) NOT NULL,
    description VARCHAR(255) NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_position PRIMARY KEY (id),
    CONSTRAINT fk_position_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_position_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_position_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT ck_position_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_position_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_position_code_active
    ON position (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_position_name_active
    ON position (name)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE position IS 'Employee job position lookup catalog ("Chức vụ" on Quản lý nhân viên - Smart mobility.png: Quản lý, Nhân viên vận hành, Nhân viên thu ngân, Kỹ thuật viên; TL-11).';
COMMENT ON COLUMN position.id IS 'Primary key identifier of the job position.';
COMMENT ON COLUMN position.code IS 'Unique business code for the position (e.g., QL, NVVH, NVTN, KTV).';
COMMENT ON COLUMN position.name IS 'Display name of the job position in Vietnamese (TL-11).';
COMMENT ON COLUMN position.description IS 'Optional description of position duties and access scope.';
COMMENT ON COLUMN position.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN position.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN position.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN position.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN position.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 2.2. Tables: administrative_province, administrative_district, administrative_ward
-- Source: Frontend `Quản lý nhân viên — Smart Mobility.png` ("Khu vực"), SRS 4.3.2 & 4.4.3, TL-11, TL-15, OQ-50, OQ-62
-- -----------------------------------------------------------------------------
CREATE TABLE administrative_province (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_administrative_province PRIMARY KEY (id),
    CONSTRAINT uq_admin_province_code UNIQUE (code),
    CONSTRAINT ck_admin_province_name_nonempty CHECK (btrim(name) <> '')
);

CREATE INDEX idx_admin_province_name ON administrative_province (name);

COMMENT ON TABLE administrative_province IS 'Provincial-level administrative division lookup ("Khu vực" on Quản lý nhân viên, SRS 4.3.2, 4.4.3, TL-11, TL-15, OQ-50, OQ-62).';
COMMENT ON COLUMN administrative_province.id IS 'Primary key identifier of the province/municipality.';
COMMENT ON COLUMN administrative_province.code IS 'Unique administrative code of the province.';
COMMENT ON COLUMN administrative_province.name IS 'Official Vietnamese name of the province or centrally-run city.';
COMMENT ON COLUMN administrative_province.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN administrative_province.updated_at IS 'Record modification timestamp.';

CREATE TABLE administrative_district (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY,
    province_id BIGINT NOT NULL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_administrative_district PRIMARY KEY (id),
    CONSTRAINT uq_admin_district_code UNIQUE (code),
    CONSTRAINT uq_admin_district_id_province UNIQUE (id, province_id),
    CONSTRAINT fk_admin_district_province FOREIGN KEY (province_id)
        REFERENCES administrative_province (id) ON DELETE RESTRICT,
    CONSTRAINT ck_admin_district_name_nonempty CHECK (btrim(name) <> '')
);

CREATE INDEX idx_admin_district_province ON administrative_district (province_id);

COMMENT ON TABLE administrative_district IS 'District-level administrative lookup ("Khu vực" on Quản lý nhân viên, SRS 4.3.2, TL-11, TL-15, OQ-50, OQ-62).';
COMMENT ON COLUMN administrative_district.id IS 'Primary key identifier of the district.';
COMMENT ON COLUMN administrative_district.province_id IS 'Foreign key referencing parent province (ON DELETE RESTRICT).';
COMMENT ON COLUMN administrative_district.code IS 'Unique administrative district code.';
COMMENT ON COLUMN administrative_district.name IS 'Vietnamese name of the district/county/town.';
COMMENT ON COLUMN administrative_district.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN administrative_district.updated_at IS 'Record modification timestamp.';

CREATE TABLE administrative_ward (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY,
    district_id BIGINT NOT NULL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_administrative_ward PRIMARY KEY (id),
    CONSTRAINT uq_admin_ward_code UNIQUE (code),
    CONSTRAINT uq_admin_ward_id_district UNIQUE (id, district_id),
    CONSTRAINT fk_admin_ward_district FOREIGN KEY (district_id)
        REFERENCES administrative_district (id) ON DELETE RESTRICT,
    CONSTRAINT ck_admin_ward_name_nonempty CHECK (btrim(name) <> '')
);

CREATE INDEX idx_admin_ward_district ON administrative_ward (district_id);

COMMENT ON TABLE administrative_ward IS 'Commune/ward-level administrative lookup (SRS 4.3.2, TL-11, TL-15, OQ-50, OQ-62).';
COMMENT ON COLUMN administrative_ward.id IS 'Primary key identifier of the ward/commune.';
COMMENT ON COLUMN administrative_ward.district_id IS 'Foreign key referencing parent district (ON DELETE RESTRICT).';
COMMENT ON COLUMN administrative_ward.code IS 'Unique administrative ward code.';
COMMENT ON COLUMN administrative_ward.name IS 'Vietnamese name of the ward/commune/township.';
COMMENT ON COLUMN administrative_ward.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN administrative_ward.updated_at IS 'Record modification timestamp.';

-- -----------------------------------------------------------------------------
-- 2.3. Table: employee
-- Source: Frontend `Quản lý nhân viên - Smart mobility.png` (Mã NV NV001..NV008 and NV0005,
--         Trạng thái Đang hoạt động / Ngừng hoạt động, Chức vụ, Khu vực), TL-11, TL-15, TL-18
-- -----------------------------------------------------------------------------
CREATE TABLE employee (
    id BIGSERIAL,
    code VARCHAR(10) NOT NULL,
    full_name VARCHAR(45) NOT NULL,
    date_of_birth DATE NULL,
    gender VARCHAR(10) NULL,
    identity_card_number VARCHAR(20) NULL,
    phone VARCHAR(15) NOT NULL,
    email VARCHAR(100) NOT NULL,
    address VARCHAR(100) NULL,
    province_id BIGINT NULL,
    district_id BIGINT NULL,
    ward_id BIGINT NULL,
    position_id BIGINT NOT NULL,
    account_id BIGINT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_employee PRIMARY KEY (id),
    CONSTRAINT fk_employee_district_hierarchy FOREIGN KEY (district_id, province_id)
        REFERENCES administrative_district (id, province_id) ON DELETE RESTRICT,
    CONSTRAINT fk_employee_ward_hierarchy FOREIGN KEY (ward_id, district_id)
        REFERENCES administrative_ward (id, district_id) ON DELETE RESTRICT,
    CONSTRAINT fk_employee_position FOREIGN KEY (position_id)
        REFERENCES position (id) ON DELETE RESTRICT,
    CONSTRAINT fk_employee_account FOREIGN KEY (account_id)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT fk_employee_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_employee_code_format CHECK (code ~ '^NV[0-9]{3,4}$'),
    CONSTRAINT ck_employee_full_name_nonempty CHECK (btrim(full_name) <> ''),
    CONSTRAINT ck_employee_dob_past CHECK (date_of_birth IS NULL OR date_of_birth < CURRENT_DATE),
    CONSTRAINT ck_employee_gender CHECK (gender IS NULL OR gender IN ('Nam', 'Nữ')),
    CONSTRAINT ck_employee_idcard_digits CHECK (identity_card_number IS NULL OR identity_card_number ~ '^[0-9]{9,20}$'),
    CONSTRAINT ck_employee_phone_digits CHECK (phone ~ '^[0-9]{9,15}$'),
    CONSTRAINT ck_employee_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT ck_employee_address_nonempty CHECK (address IS NULL OR btrim(address) <> ''),
    CONSTRAINT ck_employee_ward_requires_district CHECK (
        (ward_id IS NULL OR district_id IS NOT NULL) AND
        (district_id IS NULL OR province_id IS NOT NULL)
    ),
    CONSTRAINT ck_employee_status_enum CHECK (status IN ('ACTIVE', 'INACTIVE')),
    CONSTRAINT ck_employee_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_employee_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_employee_code_active
    ON employee (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_employee_idcard_active
    ON employee (identity_card_number)
    WHERE deleted_at IS NULL AND identity_card_number IS NOT NULL;

CREATE UNIQUE INDEX uq_employee_email_active
    ON employee (lower(email))
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_employee_phone_active
    ON employee (phone)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_employee_account_active
    ON employee (account_id)
    WHERE deleted_at IS NULL AND account_id IS NOT NULL;

CREATE INDEX idx_employee_position_id ON employee (position_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_employee_status_active ON employee (status) WHERE deleted_at IS NULL;
CREATE INDEX idx_employee_full_name ON employee (full_name) WHERE deleted_at IS NULL;
CREATE INDEX idx_employee_district_province ON employee (district_id, province_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE employee IS 'Employee HR records with code format NV + 3 or 4 digits (NV005 / NV0005), operational status (ACTIVE / INACTIVE), and 3-level address hierarchy (Quản lý nhân viên - Smart mobility.png, TL-11, TL-15, TL-18).';
COMMENT ON COLUMN employee.id IS 'Primary key identifier of the employee.';
COMMENT ON COLUMN employee.code IS 'Employee code matching ^NV[0-9]{3,4}$ (supports both NV001..NV008 and NV0005 on Quản lý nhân viên, TL-11, OQ-48).';
COMMENT ON COLUMN employee.full_name IS 'Full name of the employee ("Họ và tên", max 45 chars, required per TL-18).';
COMMENT ON COLUMN employee.date_of_birth IS 'Optional employee date of birth ("Ngày sinh", must be in the past when provided, TL-18).';
COMMENT ON COLUMN employee.gender IS 'Optional employee gender ("Giới tính": Nam or Nữ when provided, TL-18).';
COMMENT ON COLUMN employee.identity_card_number IS 'Optional national ID / CCCD number ("Số CCCD / CMND", 9-20 digits, unique among active non-null rows, TL-18).';
COMMENT ON COLUMN employee.phone IS 'Employee contact phone number ("Số điện thoại", 9-15 digits, required per TL-18).';
COMMENT ON COLUMN employee.email IS 'Employee work email address ("Email công việc", required per TL-18 and case-insensitively unique via lower(email) among active rows per TL-21, OQ-84).';
COMMENT ON COLUMN employee.address IS 'Optional detailed street address ("Địa chỉ chi tiết", TL-18).';
COMMENT ON COLUMN employee.province_id IS 'Foreign key referencing administrative_province ("Tỉnh / Thành phố", TL-11, OQ-62).';
COMMENT ON COLUMN employee.district_id IS 'Foreign key referencing administrative_district ("Quận / Huyện", TL-11, OQ-62).';
COMMENT ON COLUMN employee.ward_id IS 'Foreign key referencing administrative_ward ("Phường / Xã", TL-11, OQ-62).';
COMMENT ON COLUMN employee.position_id IS 'Foreign key referencing job position ("Chức vụ", TL-11).';
COMMENT ON COLUMN employee.account_id IS 'Optional foreign key referencing system login account (OQ-56, TL-11).';
COMMENT ON COLUMN employee.status IS 'Employment operational status: ACTIVE ("Đang hoạt động") or INACTIVE ("Ngừng hoạt động" / "Tạm nghỉ", TL-11).';
COMMENT ON COLUMN employee.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN employee.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN employee.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN employee.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN employee.deleted_by IS 'Account that performed soft deletion.';

-- =============================================================================
-- SECTION 3: CUSTOMER, BLACKLIST & VEHICLE MANAGEMENT (TL-08, TL-09, TL-15, TL-18)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 3.1. Table: customer
-- Source: Frontend `Khách hàng — Smart Mobility.png` ("Tổng khách hàng", "Đang hoạt động",
--         "Tạm ngừng", "Blacklist/Tạm khoá"), TL-08, TL-15, TL-18
-- -----------------------------------------------------------------------------
CREATE TABLE customer (
    id BIGSERIAL,
    code VARCHAR(10) NOT NULL,
    full_name VARCHAR(45) NOT NULL,
    date_of_birth DATE NULL,
    gender VARCHAR(10) NULL,
    identity_card_number VARCHAR(20) NOT NULL,
    phone VARCHAR(15) NOT NULL,
    email VARCHAR(100) NULL,
    address VARCHAR(100) NULL,
    province_id BIGINT NULL,
    district_id BIGINT NULL,
    ward_id BIGINT NULL,
    account_id BIGINT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    status_reason TEXT NULL,
    is_anonymized BOOLEAN NOT NULL DEFAULT FALSE,
    anonymized_at TIMESTAMPTZ NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_customer PRIMARY KEY (id),
    CONSTRAINT fk_customer_district_hierarchy FOREIGN KEY (district_id, province_id)
        REFERENCES administrative_district (id, province_id) ON DELETE RESTRICT,
    CONSTRAINT fk_customer_ward_hierarchy FOREIGN KEY (ward_id, district_id)
        REFERENCES administrative_ward (id, district_id) ON DELETE RESTRICT,
    CONSTRAINT fk_customer_account FOREIGN KEY (account_id)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT fk_customer_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_customer_code_format CHECK (code ~ '^[A-Za-z0-9-]+$'),
    CONSTRAINT ck_customer_full_name_nonempty CHECK (btrim(full_name) <> ''),
    CONSTRAINT ck_customer_dob_past CHECK (date_of_birth IS NULL OR date_of_birth < CURRENT_DATE),
    CONSTRAINT ck_customer_gender CHECK (gender IS NULL OR gender IN ('Nam', 'Nữ')),
    CONSTRAINT ck_customer_idcard_digits CHECK (identity_card_number ~ '^[0-9]{9,20}$'),
    CONSTRAINT ck_customer_phone_digits CHECK (phone ~ '^[0-9]{9,15}$'),
    CONSTRAINT ck_customer_email_format CHECK (email IS NULL OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT ck_customer_address_nonempty CHECK (address IS NULL OR btrim(address) <> ''),
    CONSTRAINT ck_customer_ward_requires_district CHECK (
        (ward_id IS NULL OR district_id IS NOT NULL) AND
        (district_id IS NULL OR province_id IS NOT NULL)
    ),
    CONSTRAINT ck_customer_status_enum CHECK (status IN ('ACTIVE', 'SUSPENDED', 'BLACKLISTED')),
    CONSTRAINT ck_customer_blacklist_reason CHECK (
        status <> 'BLACKLISTED' OR (status_reason IS NOT NULL AND btrim(status_reason) <> '')
    ),
    CONSTRAINT ck_customer_anonymized_pair CHECK (
        (is_anonymized = FALSE AND anonymized_at IS NULL) OR (is_anonymized = TRUE AND anonymized_at IS NOT NULL)
    ),
    CONSTRAINT ck_customer_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_customer_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_customer_code_active
    ON customer (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_customer_idcard_active
    ON customer (identity_card_number)
    WHERE deleted_at IS NULL AND is_anonymized = FALSE;

CREATE UNIQUE INDEX uq_customer_email_active
    ON customer (lower(email))
    WHERE deleted_at IS NULL AND is_anonymized = FALSE AND email IS NOT NULL;

CREATE UNIQUE INDEX uq_customer_phone_active
    ON customer (phone)
    WHERE deleted_at IS NULL AND is_anonymized = FALSE;

CREATE UNIQUE INDEX uq_customer_account_active
    ON customer (account_id)
    WHERE deleted_at IS NULL AND account_id IS NOT NULL;

CREATE INDEX idx_customer_full_name ON customer (full_name) WHERE deleted_at IS NULL;
CREATE INDEX idx_customer_status_active ON customer (status) WHERE deleted_at IS NULL;
CREATE INDEX idx_customer_district_province ON customer (district_id, province_id) WHERE deleted_at IS NULL;

-- Trigram GIN indexes for fast frontend substring/ILIKE search (TL-41, F6)
CREATE INDEX idx_customer_full_name_trgm ON customer USING gin (full_name gin_trgm_ops) WHERE deleted_at IS NULL;
CREATE INDEX idx_customer_phone_trgm ON customer USING gin (phone gin_trgm_ops) WHERE deleted_at IS NULL;
CREATE INDEX idx_customer_idcard_trgm ON customer USING gin (identity_card_number gin_trgm_ops) WHERE deleted_at IS NULL;

COMMENT ON TABLE customer IS 'Customer profile table with operational status (ACTIVE, SUSPENDED, BLACKLISTED) and status reason (Khách hàng — Smart Mobility.png, TL-08, TL-15, TL-18).';
COMMENT ON COLUMN customer.id IS 'Primary key identifier of the customer.';
COMMENT ON COLUMN customer.code IS 'Customer code ("Mã KH", e.g., KH0001..KH0004).';
COMMENT ON COLUMN customer.full_name IS 'Full name of the customer ("Họ và tên", required per TL-18).';
COMMENT ON COLUMN customer.date_of_birth IS 'Optional customer date of birth ("Ngày sinh", must be in the past when provided, TL-18).';
COMMENT ON COLUMN customer.gender IS 'Optional customer gender ("Giới tính": Nam or Nữ when provided, TL-18).';
COMMENT ON COLUMN customer.identity_card_number IS 'National ID / CCCD number ("CCCD", 9-20 digits, required per TL-18).';
COMMENT ON COLUMN customer.phone IS 'Customer phone number ("Số điện thoại", required per TL-18).';
COMMENT ON COLUMN customer.email IS 'Optional customer email address ("Email", case-insensitively unique via lower(email) among active non-anonymized non-null rows per TL-18, TL-21, OQ-84).';
COMMENT ON COLUMN customer.address IS 'Optional customer residential address ("Địa chỉ", TL-18).';
COMMENT ON COLUMN customer.province_id IS 'Optional foreign key referencing administrative_province (OQ-62).';
COMMENT ON COLUMN customer.district_id IS 'Optional foreign key referencing administrative_district (OQ-62).';
COMMENT ON COLUMN customer.ward_id IS 'Optional foreign key referencing administrative_ward (OQ-62).';
COMMENT ON COLUMN customer.account_id IS 'Optional foreign key referencing self-registered customer login account (TL-01, TL-18, OQ-55).';
COMMENT ON COLUMN customer.status IS 'Customer status: ACTIVE ("Đang hoạt động"), SUSPENDED ("Tạm ngừng"), or BLACKLISTED ("Blacklist/Tạm khoá", TL-08).';
COMMENT ON COLUMN customer.status_reason IS 'Reason for suspension or blacklisting; required when status is BLACKLISTED (TL-08).';
COMMENT ON COLUMN customer.is_anonymized IS 'Decree 13/2023/ND-CP PII anonymization flag (OQ-12).';
COMMENT ON COLUMN customer.anonymized_at IS 'Timestamp when PII anonymization was executed (OQ-12).';
COMMENT ON COLUMN customer.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN customer.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN customer.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN customer.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN customer.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 3.2. Table: plate_blacklist
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("Biển số 51G-888.88 thuộc Blacklist (Nợ phí)"), TL-08, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE plate_blacklist (
    id BIGSERIAL,
    license_plate VARCHAR(20) NOT NULL,
    license_plate_norm VARCHAR(20) GENERATED ALWAYS AS (fn_normalize_license_plate(license_plate)) STORED,
    reason TEXT NOT NULL,
    unpaid_amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    added_by BIGINT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_plate_blacklist PRIMARY KEY (id),
    CONSTRAINT fk_plate_blacklist_added_by FOREIGN KEY (added_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT fk_plate_blacklist_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_plate_blacklist_plate_nonempty CHECK (btrim(license_plate) <> ''),
    CONSTRAINT ck_plate_blacklist_plate_format CHECK (license_plate ~ '^[A-Za-z0-9 .\-]+$'),
    CONSTRAINT ck_plate_blacklist_norm_nonempty CHECK (license_plate_norm <> ''),
    CONSTRAINT ck_plate_blacklist_reason_nonempty CHECK (btrim(reason) <> ''),
    CONSTRAINT ck_plate_blacklist_unpaid_nonnegative CHECK (unpaid_amount >= 0),
    CONSTRAINT ck_plate_blacklist_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_plate_blacklist_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_plate_blacklist_norm_active
    ON plate_blacklist (license_plate_norm)
    WHERE deleted_at IS NULL AND is_active = TRUE;

COMMENT ON TABLE plate_blacklist IS 'Blacklisted license plates for visitor/unregistered vehicles with reason and unpaid debt amount ("Biển số 51G-888.88 thuộc Blacklist (Nợ phí)" on Trang chủ, TL-08).';
COMMENT ON COLUMN plate_blacklist.id IS 'Primary key identifier of the plate blacklist entry.';
COMMENT ON COLUMN plate_blacklist.license_plate IS 'Raw license plate string as entered (e.g., 51G-888.88).';
COMMENT ON COLUMN plate_blacklist.license_plate_norm IS 'Canonical normalized license plate computed via fn_normalize_license_plate(license_plate) (TL-08, TL-15, OQ-75).';
COMMENT ON COLUMN plate_blacklist.reason IS 'Mandatory reason for blacklisting the license plate (e.g., Nợ phí).';
COMMENT ON COLUMN plate_blacklist.unpaid_amount IS 'Outstanding unpaid debt amount in VND associated with the blacklisted plate (TL-08).';
COMMENT ON COLUMN plate_blacklist.is_active IS 'Whether the blacklist entry is currently active.';
COMMENT ON COLUMN plate_blacklist.added_by IS 'Optional foreign key referencing the employee who recorded the blacklist entry.';
COMMENT ON COLUMN plate_blacklist.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN plate_blacklist.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN plate_blacklist.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN plate_blacklist.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN plate_blacklist.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 3.3. Table: vehicle_type
-- Source: Frontend `Quản lý xe — Smart Mobility.png` & `Quản lý vé — Smart Mobility.png`
--         ("Ô tô", "Xe điện"), TL-09, TL-15, TL-20
-- -----------------------------------------------------------------------------
CREATE TABLE vehicle_type (
    id BIGSERIAL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(50) NOT NULL,
    description VARCHAR(255) NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_vehicle_type PRIMARY KEY (id),
    CONSTRAINT fk_vehicle_type_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_vehicle_type_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_vehicle_type_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT ck_vehicle_type_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_vehicle_type_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_vehicle_type_code_active
    ON vehicle_type (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_vehicle_type_name_active
    ON vehicle_type (name)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE vehicle_type IS 'Vehicle classification catalog ("Loại xe": Ô tô, Xe điện on Quản lý xe and Quản lý vé; cars only per TL-09, TL-20, OQ-49).';
COMMENT ON COLUMN vehicle_type.id IS 'Primary key identifier of the vehicle type.';
COMMENT ON COLUMN vehicle_type.code IS 'Unique code for the vehicle type (CAR, EV per TL-20).';
COMMENT ON COLUMN vehicle_type.name IS 'Display name of the vehicle category (Ô tô, Xe điện per TL-09, TL-20).';
COMMENT ON COLUMN vehicle_type.description IS 'Detailed description of the vehicle category.';
COMMENT ON COLUMN vehicle_type.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN vehicle_type.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN vehicle_type.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN vehicle_type.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN vehicle_type.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 3.4. Table: ticket_type
-- Source: Frontend `Quản lý vé — Smart Mobility.png` ("Vé ngày" 50.000đ, "Vé tháng" 500.000đ,
--         "Vé quý" 1.200.000đ, "Vé năm" 4.800.000đ [PROPOSAL OQ-79]), TL-10, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE ticket_type (
    id BIGSERIAL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(50) NOT NULL,
    duration_days INTEGER NOT NULL,
    default_price NUMERIC(12, 2) NOT NULL,
    description VARCHAR(255) NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_ticket_type PRIMARY KEY (id),
    CONSTRAINT fk_ticket_type_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_ticket_type_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_ticket_type_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT ck_ticket_type_duration_positive CHECK (duration_days > 0),
    CONSTRAINT ck_ticket_type_price_nonnegative CHECK (default_price >= 0),
    CONSTRAINT ck_ticket_type_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_ticket_type_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_ticket_type_code_active
    ON ticket_type (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_ticket_type_name_active
    ON ticket_type (name)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE ticket_type IS 'Ticket tariff catalog ("Loại vé" on Quản lý vé: Vé ngày 50.000đ, Vé tháng 500.000đ, Vé quý 1.200.000đ, Vé năm 4.800.000đ [PROPOSAL OQ-79], TL-10).';
COMMENT ON COLUMN ticket_type.id IS 'Primary key identifier of the ticket type.';
COMMENT ON COLUMN ticket_type.code IS 'Unique code of the ticket type (DAILY, MONTHLY, QUARTERLY, YEARLY).';
COMMENT ON COLUMN ticket_type.name IS 'Display name of the ticket type in Vietnamese (Vé ngày, Vé tháng, Vé quý, Vé năm).';
COMMENT ON COLUMN ticket_type.duration_days IS 'Validity duration in calendar days (1, 30, 90, 365).';
COMMENT ON COLUMN ticket_type.default_price IS 'Default standard tariff price in VND (NUMERIC(12,2)).';
COMMENT ON COLUMN ticket_type.description IS 'Optional tariff description and policy notes.';
COMMENT ON COLUMN ticket_type.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN ticket_type.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN ticket_type.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN ticket_type.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN ticket_type.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 3.5. Table: vehicle
-- Source: Frontend `Quản lý xe — Smart Mobility.png` (Mã xe, Ảnh, Biển số & Thông tin xe,
--         Loại xe, Chủ sở hữu, Vé liên kết, Ghi chú), TL-09, TL-15, OQ-52, OQ-53, OQ-75
-- -----------------------------------------------------------------------------
CREATE TABLE vehicle (
    id BIGSERIAL,
    code VARCHAR(10) NOT NULL,
    license_plate VARCHAR(20) NOT NULL,
    license_plate_norm VARCHAR(20) GENERATED ALWAYS AS (fn_normalize_license_plate(license_plate)) STORED,
    model_name VARCHAR(50) NOT NULL,
    brand VARCHAR(50) NULL,
    color VARCHAR(30) NULL,
    image_url TEXT NULL,
    notes TEXT NULL,
    vehicle_type_id BIGINT NOT NULL,
    customer_id BIGINT NOT NULL,
    ticket_type_id BIGINT NULL,
    ticket_expires_at TIMESTAMPTZ NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_vehicle PRIMARY KEY (id),
    CONSTRAINT uq_vehicle_id_customer UNIQUE (id, customer_id),
    CONSTRAINT fk_vehicle_type FOREIGN KEY (vehicle_type_id)
        REFERENCES vehicle_type (id) ON DELETE RESTRICT,
    CONSTRAINT fk_vehicle_customer FOREIGN KEY (customer_id)
        REFERENCES customer (id) ON DELETE RESTRICT,
    CONSTRAINT fk_vehicle_ticket_type FOREIGN KEY (ticket_type_id)
        REFERENCES ticket_type (id) ON DELETE RESTRICT,
    CONSTRAINT fk_vehicle_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_vehicle_code_format CHECK (code ~ '^[A-Za-z0-9-]+$'),
    CONSTRAINT ck_vehicle_license_plate_nonempty CHECK (btrim(license_plate) <> ''),
    CONSTRAINT ck_vehicle_license_plate_format CHECK (license_plate ~ '^[A-Za-z0-9 .\-]+$'),
    CONSTRAINT ck_vehicle_license_plate_norm_nonempty CHECK (license_plate_norm <> ''),
    CONSTRAINT ck_vehicle_model_name_nonempty CHECK (btrim(model_name) <> ''),
    CONSTRAINT ck_vehicle_ticket_pref_pair CHECK (
        (ticket_type_id IS NULL AND ticket_expires_at IS NULL) OR
        (ticket_type_id IS NOT NULL AND ticket_expires_at IS NOT NULL)
    ),
    CONSTRAINT ck_vehicle_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_vehicle_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_vehicle_code_active
    ON vehicle (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_vehicle_license_plate_active
    ON vehicle (license_plate_norm)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_vehicle_customer_id ON vehicle (customer_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_vehicle_type_id ON vehicle (vehicle_type_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_vehicle_ticket_type_id ON vehicle (ticket_type_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_vehicle_plate_trgm ON vehicle USING gin (license_plate_norm gin_trgm_ops) WHERE deleted_at IS NULL;

COMMENT ON TABLE vehicle IS 'Customer registered vehicles with raw display license_plate, stored generated license_plate_norm, image_url ("Ảnh"), and notes ("Ghi chú" on Quản lý xe — Smart Mobility.png, TL-09, TL-15, OQ-75).';
COMMENT ON COLUMN vehicle.id IS 'Primary key identifier of the vehicle.';
COMMENT ON COLUMN vehicle.code IS 'Vehicle business code ("Mã xe", e.g., XE0001..XE0008).';
COMMENT ON COLUMN vehicle.license_plate IS 'Raw license plate string preserved as entered for UI display (e.g., 51K-992.14, 51K-992-14).';
COMMENT ON COLUMN vehicle.license_plate_norm IS 'Canonical normalized license plate computed via fn_normalize_license_plate(license_plate) for uniqueness and barrier matching (TL-15, OQ-75).';
COMMENT ON COLUMN vehicle.model_name IS 'Commercial vehicle model name (e.g., Camry 2.5Q, Mazda CX-5, VF 8 Plus).';
COMMENT ON COLUMN vehicle.brand IS 'Vehicle manufacturer brand (e.g., Toyota, Mazda, VinFast; nullable per OQ-53).';
COMMENT ON COLUMN vehicle.color IS 'Exterior color of the vehicle (e.g., Trắng, Đen, Xanh rêu).';
COMMENT ON COLUMN vehicle.image_url IS 'Optional vehicle photo URI/path ("Ảnh" column on Quản lý xe — Smart Mobility.png, TL-09).';
COMMENT ON COLUMN vehicle.notes IS 'Optional free-text vehicle notes ("Ghi chú" column and "Ghi chú phương tiện" on Quản lý xe — Smart Mobility.png, TL-09).';
COMMENT ON COLUMN vehicle.vehicle_type_id IS 'Foreign key referencing vehicle_type ("Loại xe": Ô tô, Xe điện per TL-09, TL-20).';
COMMENT ON COLUMN vehicle.customer_id IS 'Foreign key referencing the owning customer ("Chủ sở hữu (Khách hàng)").';
COMMENT ON COLUMN vehicle.ticket_type_id IS 'Synchronized active ticket type preference (OQ-52, TL-15).';
COMMENT ON COLUMN vehicle.ticket_expires_at IS 'Synchronized active ticket expiration timestamp (OQ-52, TL-15).';
COMMENT ON COLUMN vehicle.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN vehicle.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN vehicle.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN vehicle.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN vehicle.deleted_by IS 'Account that performed soft deletion.';

-- =============================================================================
-- SECTION 4: PARKING FACILITY HIERARCHY, SLOTS & RESERVATIONS (TL-02, TL-03, TL-04)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 4.1. Table: parking_lot
-- Source: Frontend `Sơ đồ bãi đậu xe — Smart Mobility.png` & `Trang chủ — Smart Mobility.png`
--         ("Bãi đỗ xe: Bãi xe Smart Mobility"), TL-02, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE parking_lot (
    id BIGSERIAL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    address VARCHAR(255) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_parking_lot PRIMARY KEY (id),
    CONSTRAINT fk_parking_lot_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_parking_lot_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_parking_lot_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT ck_parking_lot_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_parking_lot_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_parking_lot_code_active
    ON parking_lot (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_parking_lot_name_active
    ON parking_lot (name)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE parking_lot IS 'Top-level parking facility entity ("Bãi đỗ xe: Bãi xe Smart Mobility" on Sơ đồ bãi đậu xe and Trang chủ, TL-02).';
COMMENT ON COLUMN parking_lot.id IS 'Primary key identifier of the parking lot.';
COMMENT ON COLUMN parking_lot.code IS 'Unique code of the parking lot (e.g., SMART_MOBILITY).';
COMMENT ON COLUMN parking_lot.name IS 'Display name of the parking lot (e.g., Bãi xe Smart Mobility).';
COMMENT ON COLUMN parking_lot.address IS 'Physical address or location description of the parking lot.';
COMMENT ON COLUMN parking_lot.is_active IS 'Whether the parking facility is currently active.';
COMMENT ON COLUMN parking_lot.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN parking_lot.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN parking_lot.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN parking_lot.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN parking_lot.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 4.1.1. Table: booking_policy
-- Source: Advance Slot Booking Management Module (R1.3, OQ-87)
-- 1-1 policy configuration table per parking lot.
-- -----------------------------------------------------------------------------
CREATE TABLE booking_policy (
    id BIGSERIAL,
    lot_id BIGINT NOT NULL,
    hold_minutes INTEGER NOT NULL DEFAULT 15,
    grace_minutes INTEGER NOT NULL DEFAULT 15,
    early_checkin_minutes INTEGER NOT NULL DEFAULT 15,
    max_advance_days INTEGER NOT NULL DEFAULT 7,
    min_duration_minutes INTEGER NOT NULL DEFAULT 30,
    max_duration_minutes INTEGER NOT NULL DEFAULT 1440,
    deposit_amount NUMERIC(12, 2) NOT NULL DEFAULT 50000.00,
    cancel_free_before_minutes INTEGER NOT NULL DEFAULT 60,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_booking_policy PRIMARY KEY (id),
    CONSTRAINT fk_booking_policy_lot FOREIGN KEY (lot_id)
        REFERENCES parking_lot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_booking_policy_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_booking_policy_hold_minutes CHECK (hold_minutes > 0),
    CONSTRAINT ck_booking_policy_grace_minutes CHECK (grace_minutes >= 0),
    CONSTRAINT ck_booking_policy_early_checkin_minutes CHECK (early_checkin_minutes >= 0),
    CONSTRAINT ck_booking_policy_max_advance_days CHECK (max_advance_days >= 1),
    CONSTRAINT ck_booking_policy_min_duration CHECK (min_duration_minutes >= 15),
    CONSTRAINT ck_booking_policy_max_duration CHECK (max_duration_minutes >= min_duration_minutes),
    CONSTRAINT ck_booking_policy_deposit_amount CHECK (deposit_amount >= 0.00),
    CONSTRAINT ck_booking_policy_cancel_free CHECK (cancel_free_before_minutes >= 0),
    CONSTRAINT ck_booking_policy_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_booking_policy_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_booking_policy_lot_active
    ON booking_policy (lot_id)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE booking_policy IS 'Advance slot booking policy configuration parameters (1-to-1 with parking_lot, R1.3, OQ-87).';
COMMENT ON COLUMN booking_policy.id IS 'Primary key identifier of the booking policy.';
COMMENT ON COLUMN booking_policy.lot_id IS 'Foreign key referencing parent parking_lot (ON DELETE RESTRICT, 1-to-1 active).';
COMMENT ON COLUMN booking_policy.hold_minutes IS 'Duration in minutes to hold a pending booking before deposit settlement (default 15).';
COMMENT ON COLUMN booking_policy.grace_minutes IS 'Grace arrival window in minutes past reserved_from before marking NO_SHOW (default 15).';
COMMENT ON COLUMN booking_policy.early_checkin_minutes IS 'Permitted early arrival window in minutes before reserved_from (default 15).';
COMMENT ON COLUMN booking_policy.max_advance_days IS 'Maximum days in advance a slot can be booked (default 7).';
COMMENT ON COLUMN booking_policy.min_duration_minutes IS 'Minimum booking duration in minutes (default 30).';
COMMENT ON COLUMN booking_policy.max_duration_minutes IS 'Maximum booking duration in minutes (default 1440 = 24 hours).';
COMMENT ON COLUMN booking_policy.deposit_amount IS 'Required booking deposit amount in VND (NUMERIC(12,2), default 50000.00).';
COMMENT ON COLUMN booking_policy.cancel_free_before_minutes IS 'Lead time in minutes before reserved_from for 100% deposit refund upon cancellation (default 60).';
COMMENT ON COLUMN booking_policy.is_active IS 'Whether this booking policy is currently active.';
COMMENT ON COLUMN booking_policy.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN booking_policy.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN booking_policy.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN booking_policy.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN booking_policy.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 4.2. Table: parking_floor
-- Source: Frontend `Sơ đồ bãi đậu xe — Smart Mobility.png` ("+ Thêm tầng", "Tầng B1",
--         "Tầng B2", "Tầng F1 - Ngoài trời", panel "Quản lý cấu trúc bãi"), TL-02
-- -----------------------------------------------------------------------------
CREATE TABLE parking_floor (
    id BIGSERIAL,
    lot_id BIGINT NOT NULL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(50) NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 1,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_parking_floor PRIMARY KEY (id),
    CONSTRAINT fk_parking_floor_lot FOREIGN KEY (lot_id)
        REFERENCES parking_lot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_parking_floor_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_parking_floor_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_parking_floor_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT ck_parking_floor_sort_positive CHECK (sort_order > 0),
    CONSTRAINT ck_parking_floor_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_parking_floor_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_parking_floor_lot_code_active
    ON parking_floor (lot_id, code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_parking_floor_lot_name_active
    ON parking_floor (lot_id, name)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_parking_floor_lot_id ON parking_floor (lot_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE parking_floor IS 'Named parking floor within a parking lot ("Tầng B1", "Tầng B2", "Tầng F1" on Sơ đồ bãi đậu xe, TL-02).';
COMMENT ON COLUMN parking_floor.id IS 'Primary key identifier of the parking floor.';
COMMENT ON COLUMN parking_floor.lot_id IS 'Foreign key referencing parent parking_lot (ON DELETE RESTRICT).';
COMMENT ON COLUMN parking_floor.code IS 'Short string code of the floor within the lot (e.g., B1, B2, B3, F1).';
COMMENT ON COLUMN parking_floor.name IS 'Display name of the floor (e.g., Tầng B1, Tầng F1 - Ngoài trời).';
COMMENT ON COLUMN parking_floor.sort_order IS 'Positive display ordering of the floor in UI tabs and trees.';
COMMENT ON COLUMN parking_floor.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN parking_floor.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN parking_floor.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN parking_floor.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN parking_floor.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 4.3. Table: parking_zone
-- Source: Frontend `Sơ đồ bãi đậu xe — Smart Mobility.png` ("+ Thêm khu", "Khu A".."Khu D",
--         "Khu VIP", panel "Quản lý cấu trúc bãi"), TL-02
-- -----------------------------------------------------------------------------
CREATE TABLE parking_zone (
    id BIGSERIAL,
    floor_id BIGINT NOT NULL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(50) NOT NULL,
    description TEXT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_parking_zone PRIMARY KEY (id),
    CONSTRAINT fk_parking_zone_floor FOREIGN KEY (floor_id)
        REFERENCES parking_floor (id) ON DELETE RESTRICT,
    CONSTRAINT fk_parking_zone_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_parking_zone_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_parking_zone_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT ck_parking_zone_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_parking_zone_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_parking_zone_floor_code_active
    ON parking_zone (floor_id, code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_parking_zone_floor_name_active
    ON parking_zone (floor_id, name)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_parking_zone_floor_id ON parking_zone (floor_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE parking_zone IS 'Named parking zone within a floor ("Khu A".."Khu D", "Khu VIP" on Sơ đồ bãi đậu xe, TL-02).';
COMMENT ON COLUMN parking_zone.id IS 'Primary key identifier of the parking zone.';
COMMENT ON COLUMN parking_zone.floor_id IS 'Foreign key referencing parent parking_floor (ON DELETE RESTRICT).';
COMMENT ON COLUMN parking_zone.code IS 'Short code of the zone within the floor (e.g., KHU_A, A, VIP).';
COMMENT ON COLUMN parking_zone.name IS 'Display name of the zone (e.g., Khu A, Khu VIP).';
COMMENT ON COLUMN parking_zone.description IS 'Optional description of the zone (e.g., Dãy ô tô tiêu chuẩn, Khu sạc xe điện).';
COMMENT ON COLUMN parking_zone.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN parking_zone.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN parking_zone.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN parking_zone.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN parking_zone.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 4.4. Table: parking_slot
-- Source: Frontend `Sơ đồ bãi đậu xe — Smart Mobility.png` & `Main Page.png`
--         (code "A-01", slot_kind STANDARD/PRIORITY/EV_CHARGING, 5 statuses AVAILABLE/
--         OCCUPIED/RESERVED/CHARGING/MAINTENANCE, "Ghi chú", grid coordinates & dimensions),
--         TL-02, TL-03, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE parking_slot (
    id BIGSERIAL,
    zone_id BIGINT NOT NULL,
    code VARCHAR(20) NOT NULL,
    slot_kind VARCHAR(20) NOT NULL DEFAULT 'STANDARD',
    status VARCHAR(20) NOT NULL DEFAULT 'AVAILABLE',
    map_row SMALLINT NULL,
    map_col SMALLINT NULL,
    width NUMERIC(5, 2) NOT NULL DEFAULT 2.50,
    length NUMERIC(5, 2) NOT NULL DEFAULT 5.00,
    height NUMERIC(5, 2) NOT NULL DEFAULT 2.20,
    notes TEXT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_parking_slot PRIMARY KEY (id),
    CONSTRAINT fk_slot_zone FOREIGN KEY (zone_id)
        REFERENCES parking_zone (id) ON DELETE RESTRICT,
    CONSTRAINT fk_slot_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_slot_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_slot_code_format CHECK (code ~ '^[A-Za-z0-9 .\-]+$'),
    CONSTRAINT ck_slot_kind_enum CHECK (slot_kind IN ('STANDARD', 'PRIORITY', 'EV_CHARGING')),
    CONSTRAINT ck_slot_status_enum CHECK (
        status IN ('AVAILABLE', 'OCCUPIED', 'RESERVED', 'CHARGING', 'MAINTENANCE')
    ),
    CONSTRAINT ck_slot_charging_requires_ev_kind CHECK (
        status <> 'CHARGING' OR slot_kind = 'EV_CHARGING'
    ),
    CONSTRAINT ck_slot_map_coords_pair CHECK (
        (map_row IS NULL AND map_col IS NULL) OR
        (map_row IS NOT NULL AND map_col IS NOT NULL AND map_row > 0 AND map_col > 0)
    ),
    CONSTRAINT ck_slot_dimensions_positive CHECK (width > 0 AND length > 0 AND height > 0),
    CONSTRAINT ck_slot_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_slot_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_parking_slot_zone_code_active
    ON parking_slot (zone_id, code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_parking_slot_zone_map_pos_active
    ON parking_slot (zone_id, map_row, map_col)
    WHERE deleted_at IS NULL AND map_row IS NOT NULL AND map_col IS NOT NULL;

CREATE INDEX idx_parking_slot_status_active
    ON parking_slot (zone_id, status)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE parking_slot IS 'Physical parking slot belonging to a parking_zone with 5 operational statuses, 3 slot kinds, 2D map coordinates, physical dimensions, and free-text notes (Sơ đồ bãi đậu xe — Smart Mobility.png, Main Page.png, TL-02, TL-03).';
COMMENT ON COLUMN parking_slot.id IS 'Primary key identifier of the parking slot.';
COMMENT ON COLUMN parking_slot.zone_id IS 'Foreign key referencing parent parking_zone (TL-02).';
COMMENT ON COLUMN parking_slot.code IS 'Display code of the slot within the zone (e.g., A-01, A10, B-01, Slot 42; TL-02).';
COMMENT ON COLUMN parking_slot.slot_kind IS 'Physical classification of the slot: STANDARD (tiêu chuẩn), PRIORITY (xe ưu tiên), or EV_CHARGING (sạc xe điện) (TL-03).';
COMMENT ON COLUMN parking_slot.status IS 'Operational status: AVAILABLE (Trống), OCCUPIED (Đang có xe), RESERVED (Đã đặt trước), CHARGING (Sạc xe điện), or MAINTENANCE (Bảo trì) (TL-03).';
COMMENT ON COLUMN parking_slot.map_row IS '1-based row coordinate on the 2D zone/floor map grid (TL-02, OQ-69).';
COMMENT ON COLUMN parking_slot.map_col IS '1-based column coordinate on the 2D zone/floor map grid (TL-02, OQ-69).';
COMMENT ON COLUMN parking_slot.width IS 'Slot width in meters (must be > 0, SRS 4.8.2, TL-02).';
COMMENT ON COLUMN parking_slot.length IS 'Slot length in meters (must be > 0, SRS 4.8.2, TL-02).';
COMMENT ON COLUMN parking_slot.height IS 'Slot height clearance in meters (must be > 0, SRS 4.8.2, TL-02).';
COMMENT ON COLUMN parking_slot.notes IS 'Optional free-text note for the slot ("Ghi chú" in Chi tiết ô đỗ on Sơ đồ bãi đậu xe, TL-03).';
COMMENT ON COLUMN parking_slot.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN parking_slot.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN parking_slot.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN parking_slot.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN parking_slot.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 4.5. Table: slot_allowed_vehicle_type
-- Source: Frontend `Sơ đồ bãi đậu xe — Smart Mobility.png` ("Loại xe: Ô tô 4-7 chỗ"), TL-03, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE slot_allowed_vehicle_type (
    slot_id BIGINT NOT NULL,
    vehicle_type_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_slot_allowed_vehicle_type PRIMARY KEY (slot_id, vehicle_type_id),
    CONSTRAINT fk_savt_slot FOREIGN KEY (slot_id)
        REFERENCES parking_slot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_savt_vehicle_type FOREIGN KEY (vehicle_type_id)
        REFERENCES vehicle_type (id) ON DELETE RESTRICT
);

CREATE INDEX idx_savt_vehicle_type_id ON slot_allowed_vehicle_type (vehicle_type_id);

COMMENT ON TABLE slot_allowed_vehicle_type IS 'Many-to-many junction specifying permitted vehicle_type categories per parking_slot (TL-03, TL-15, SRS 4.8.2).';
COMMENT ON COLUMN slot_allowed_vehicle_type.slot_id IS 'Foreign key referencing parking_slot.';
COMMENT ON COLUMN slot_allowed_vehicle_type.vehicle_type_id IS 'Foreign key referencing allowed vehicle_type.';
COMMENT ON COLUMN slot_allowed_vehicle_type.created_at IS 'Association creation timestamp.';

-- -----------------------------------------------------------------------------
-- 4.6. Table: slot_reservation
-- Source: Frontend `Sơ đồ bãi đậu xe — Smart Mobility.png` ("ĐÃ ĐẶT 13:30", "Người đặt trước",
--         "Đặt trước ô A-04 cho xe 30E-456.78 lúc 13:30"), TL-04, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE slot_reservation (
    id BIGSERIAL,
    code VARCHAR(30) NOT NULL,
    slot_id BIGINT NOT NULL,
    customer_id BIGINT NULL,
    vehicle_id BIGINT NULL,
    booking_channel VARCHAR(20) NOT NULL DEFAULT 'CUSTOMER_PORTAL',
    reserved_name VARCHAR(100) NULL,
    reserved_phone VARCHAR(15) NULL,
    reserved_from TIMESTAMPTZ NOT NULL,
    reserved_until TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'CONFIRMED',
    hold_expires_at TIMESTAMPTZ NULL,
    deposit_amount NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    checked_in_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL,
    cancelled_by BIGINT NULL,
    cancel_reason TEXT NULL,
    no_show_at TIMESTAMPTZ NULL,
    notes TEXT NULL,
    created_by BIGINT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_slot_reservation PRIMARY KEY (id),
    CONSTRAINT fk_reservation_slot FOREIGN KEY (slot_id)
        REFERENCES parking_slot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_reservation_customer FOREIGN KEY (customer_id)
        REFERENCES customer (id) ON DELETE RESTRICT,
    CONSTRAINT fk_reservation_vehicle FOREIGN KEY (vehicle_id)
        REFERENCES vehicle (id) ON DELETE RESTRICT,
    CONSTRAINT fk_reservation_cancelled_by FOREIGN KEY (cancelled_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT fk_reservation_created_by FOREIGN KEY (created_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT fk_reservation_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_reservation_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_reservation_time_order CHECK (reserved_until > reserved_from),
    CONSTRAINT ck_reservation_status_enum CHECK (
        status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN', 'COMPLETED', 'CANCELLED', 'EXPIRED', 'NO_SHOW')
    ),
    CONSTRAINT ck_reservation_booking_channel_enum CHECK (
        booking_channel IN ('CUSTOMER_PORTAL', 'STAFF')
    ),
    CONSTRAINT ck_reservation_deposit_amount_nonnegative CHECK (
        deposit_amount >= 0.00
    ),
    CONSTRAINT ck_reservation_phone_digits CHECK (
        reserved_phone IS NULL OR reserved_phone ~ '^[0-9]{9,15}$'
    ),
    CONSTRAINT ck_reservation_channel_requirements CHECK (
        (booking_channel = 'CUSTOMER_PORTAL' AND customer_id IS NOT NULL AND vehicle_id IS NOT NULL)
        OR
        (booking_channel = 'STAFF' AND (
            (customer_id IS NOT NULL AND vehicle_id IS NOT NULL)
            OR (btrim(COALESCE(reserved_name, '')) <> '' AND reserved_phone IS NOT NULL)
        ))
    ),
    CONSTRAINT ck_reservation_hold_expires_rule CHECK (
        (status = 'PENDING_PAYMENT' AND hold_expires_at IS NOT NULL)
        OR (status <> 'PENDING_PAYMENT')
    ),
    CONSTRAINT ck_reservation_cancellation_pair CHECK (
        (status = 'CANCELLED' AND cancelled_at IS NOT NULL)
        OR (status <> 'CANCELLED')
    ),
    CONSTRAINT ck_reservation_no_show_pair CHECK (
        (status = 'NO_SHOW' AND no_show_at IS NOT NULL)
        OR (status <> 'NO_SHOW')
    ),
    CONSTRAINT ck_reservation_checked_in_pair CHECK (
        (status = 'CHECKED_IN' AND checked_in_at IS NOT NULL)
        OR (status <> 'CHECKED_IN')
    ),
    CONSTRAINT ck_reservation_completed_pair CHECK (
        (status = 'COMPLETED' AND completed_at IS NOT NULL)
        OR (status <> 'COMPLETED')
    ),
    CONSTRAINT ck_reservation_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_reservation_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    ),
    CONSTRAINT excl_reservation_slot_time_overlap EXCLUDE USING gist (
        slot_id WITH =,
        tstzrange(reserved_from, reserved_until, '[)') WITH &&
    ) WHERE (deleted_at IS NULL AND status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN')),
    CONSTRAINT excl_reservation_vehicle_time_overlap EXCLUDE USING gist (
        vehicle_id WITH =,
        tstzrange(reserved_from, reserved_until, '[)') WITH &&
    ) WHERE (deleted_at IS NULL AND vehicle_id IS NOT NULL AND status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN'))
);

CREATE UNIQUE INDEX uq_reservation_code_active
    ON slot_reservation (code)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_reservation_slot_status
    ON slot_reservation (slot_id, status)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_slot_reservation_customer_id ON slot_reservation (customer_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_slot_reservation_vehicle_id ON slot_reservation (vehicle_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_slot_reservation_cancelled_by ON slot_reservation (cancelled_by) WHERE deleted_at IS NULL;
CREATE INDEX idx_slot_reservation_hold_expires ON slot_reservation (hold_expires_at) WHERE deleted_at IS NULL AND status = 'PENDING_PAYMENT';

COMMENT ON TABLE slot_reservation IS 'Advance parking slot reservations with multi-state GiST anti-overlap and vehicle anti-double-booking exclusions (R1.1, R1.2, TL-04, OQ-88).';
COMMENT ON COLUMN slot_reservation.id IS 'Primary key identifier of the slot reservation.';
COMMENT ON COLUMN slot_reservation.code IS 'Unique reservation reference code among active records.';
COMMENT ON COLUMN slot_reservation.slot_id IS 'Foreign key referencing the reserved parking_slot.';
COMMENT ON COLUMN slot_reservation.customer_id IS 'Optional foreign key referencing a registered customer.';
COMMENT ON COLUMN slot_reservation.vehicle_id IS 'Optional foreign key referencing a registered vehicle.';
COMMENT ON COLUMN slot_reservation.booking_channel IS 'Booking origination channel: CUSTOMER_PORTAL or STAFF (R1.2).';
COMMENT ON COLUMN slot_reservation.reserved_name IS 'Display name of the reserver when booked for a walk-in/visitor ("Người đặt trước", TL-04).';
COMMENT ON COLUMN slot_reservation.reserved_phone IS 'Contact phone number of the reserver.';
COMMENT ON COLUMN slot_reservation.reserved_from IS 'Reservation start timestamp (inclusive lower bound).';
COMMENT ON COLUMN slot_reservation.reserved_until IS 'Reservation end timestamp (exclusive upper bound, must be > reserved_from).';
COMMENT ON COLUMN slot_reservation.status IS 'Reservation lifecycle status: PENDING_PAYMENT, CONFIRMED, CHECKED_IN, COMPLETED, CANCELLED, EXPIRED, or NO_SHOW (R1.1, OQ-88).';
COMMENT ON COLUMN slot_reservation.hold_expires_at IS 'Expiration deadline for settling booking deposit while in PENDING_PAYMENT.';
COMMENT ON COLUMN slot_reservation.deposit_amount IS 'Booking deposit amount in VND (NUMERIC(12,2), default 0.00).';
COMMENT ON COLUMN slot_reservation.checked_in_at IS 'Timestamp when the reserver vehicle checked in at the entry barrier.';
COMMENT ON COLUMN slot_reservation.completed_at IS 'Timestamp when the parking session exited, completing the reservation.';
COMMENT ON COLUMN slot_reservation.cancelled_at IS 'Timestamp when the reservation was cancelled.';
COMMENT ON COLUMN slot_reservation.cancelled_by IS 'Foreign key referencing the account that cancelled the reservation.';
COMMENT ON COLUMN slot_reservation.cancel_reason IS 'Reason or note explaining why the reservation was cancelled.';
COMMENT ON COLUMN slot_reservation.no_show_at IS 'Timestamp when the reservation was marked NO_SHOW after grace expiration.';
COMMENT ON COLUMN slot_reservation.notes IS 'Optional reservation notes.';
COMMENT ON COLUMN slot_reservation.created_by IS 'Optional foreign key referencing the employee who created the reservation.';
COMMENT ON COLUMN slot_reservation.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN slot_reservation.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN slot_reservation.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN slot_reservation.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN slot_reservation.deleted_by IS 'Account that performed soft deletion.';

-- =============================================================================
-- SECTION 5: TICKETING & RENEWAL MODULE (TL-10, TL-15, SRS 4.6)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 5.1. Table: ticket
-- Source: Frontend `Quản lý vé — Smart Mobility.png` (main list & 3 dialogs:
--         "Thêm vé mới", "Gia hạn vé", "Chi tiết vé"; statuses ACTIVE, EXPIRED,
--         CANCELLED, RENEWING; "Sắp hết hạn" is derived from dates; "Ghi chú"), TL-10, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE ticket (
    id BIGSERIAL,
    code VARCHAR(10) NOT NULL,
    vehicle_id BIGINT NOT NULL,
    customer_id BIGINT NOT NULL,
    slot_id BIGINT NOT NULL,
    ticket_type_id BIGINT NOT NULL,
    issued_by BIGINT NULL,
    price NUMERIC(12, 2) NOT NULL,
    effective_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    effective_to TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    notes TEXT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_ticket PRIMARY KEY (id),
    CONSTRAINT fk_ticket_vehicle_customer FOREIGN KEY (vehicle_id, customer_id)
        REFERENCES vehicle (id, customer_id) ON DELETE RESTRICT,
    CONSTRAINT fk_ticket_customer FOREIGN KEY (customer_id)
        REFERENCES customer (id) ON DELETE RESTRICT,
    CONSTRAINT fk_ticket_slot FOREIGN KEY (slot_id)
        REFERENCES parking_slot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_ticket_type FOREIGN KEY (ticket_type_id)
        REFERENCES ticket_type (id) ON DELETE RESTRICT,
    CONSTRAINT fk_ticket_issued_by FOREIGN KEY (issued_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT fk_ticket_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_ticket_code_format CHECK (code ~ '^[A-Za-z0-9-]+$'),
    CONSTRAINT ck_ticket_price_nonnegative CHECK (price >= 0),
    CONSTRAINT ck_ticket_time_order CHECK (effective_to > effective_from),
    CONSTRAINT ck_ticket_status_enum CHECK (
        status IN ('ACTIVE', 'EXPIRED', 'CANCELLED', 'RENEWING')
    ),
    CONSTRAINT ck_ticket_delete_only_expired CHECK (
        deleted_at IS NULL OR effective_to <= deleted_at
    ),
    CONSTRAINT ck_ticket_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_ticket_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    ),
    CONSTRAINT excl_ticket_slot_time_overlap EXCLUDE USING gist (
        slot_id WITH =,
        tstzrange(effective_from, effective_to, '[)') WITH &&
    ) WHERE (deleted_at IS NULL AND status IN ('ACTIVE', 'RENEWING'))
);

CREATE UNIQUE INDEX uq_ticket_code_active
    ON ticket (code)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_ticket_customer_id ON ticket (customer_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_ticket_vehicle_id ON ticket (vehicle_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_ticket_slot_id ON ticket (slot_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_ticket_ticket_type_id ON ticket (ticket_type_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_ticket_status_effective ON ticket (status, effective_to) WHERE deleted_at IS NULL;
CREATE INDEX idx_ticket_stat_active ON ticket (created_at) WHERE deleted_at IS NULL;

COMMENT ON TABLE ticket IS 'Issued parking tickets with GiST non-overlapping slot exclusion, composite vehicle-customer ownership FK, notes, and statuses ACTIVE, EXPIRED, CANCELLED, RENEWING ("Sắp hết hạn" is derived from effective_to; Quản lý vé — Smart Mobility.png, TL-10, TL-15).';
COMMENT ON COLUMN ticket.id IS 'Primary key identifier of the ticket.';
COMMENT ON COLUMN ticket.code IS 'Unique ticket business code ("Mã vé", e.g., VT0001..VT0006).';
COMMENT ON COLUMN ticket.vehicle_id IS 'Foreign key referencing registered vehicle (part of composite FK with customer_id per OQ-61).';
COMMENT ON COLUMN ticket.customer_id IS 'Foreign key referencing ticket owner customer.';
COMMENT ON COLUMN ticket.slot_id IS 'Foreign key referencing assigned physical parking_slot.';
COMMENT ON COLUMN ticket.ticket_type_id IS 'Foreign key referencing tariff ticket_type.';
COMMENT ON COLUMN ticket.issued_by IS 'Optional foreign key referencing the employee who issued the ticket.';
COMMENT ON COLUMN ticket.price IS 'Billed ticket price in VND ("Giá vé (VNĐ)").';
COMMENT ON COLUMN ticket.effective_from IS 'Ticket validity start timestamp ("Ngày bắt đầu").';
COMMENT ON COLUMN ticket.effective_to IS 'Ticket validity end timestamp ("Ngày kết thúc", must be > effective_from).';
COMMENT ON COLUMN ticket.status IS 'Stored ticket lifecycle status: ACTIVE (Đang hiệu lực), EXPIRED (Hết hạn), CANCELLED (Đã hủy), or RENEWING (Đang gia hạn); "Sắp hết hạn" is derived from effective_to (TL-10).';
COMMENT ON COLUMN ticket.notes IS 'Optional ticket notes ("Ghi chú" on Thêm vé mới and Chi tiết vé dialogs, TL-10).';
COMMENT ON COLUMN ticket.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN ticket.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN ticket.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN ticket.deleted_at IS 'Soft deletion timestamp; permitted only after expiration (ck_ticket_delete_only_expired, OQ-64).';
COMMENT ON COLUMN ticket.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 5.2. Table: ticket_renewal
-- Source: Frontend `Quản lý vé — Smart Mobility.png` (Dialog 2 "Gia hạn vé" & Dialog 3
--         "Lịch sử gia hạn", including "Ghi chú gia hạn"), TL-10, TL-15, OQ-58
-- -----------------------------------------------------------------------------
CREATE TABLE ticket_renewal (
    id BIGSERIAL,
    ticket_id BIGINT NOT NULL,
    old_slot_id BIGINT NOT NULL,
    new_slot_id BIGINT NOT NULL,
    old_ticket_type_id BIGINT NULL,
    new_ticket_type_id BIGINT NULL,
    old_price NUMERIC(12, 2) NULL,
    new_price NUMERIC(12, 2) NULL,
    old_effective_to TIMESTAMPTZ NOT NULL,
    new_effective_to TIMESTAMPTZ NOT NULL,
    additional_price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    notes TEXT NULL,
    renewed_by BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT pk_ticket_renewal PRIMARY KEY (id),
    CONSTRAINT fk_renewal_ticket FOREIGN KEY (ticket_id)
        REFERENCES ticket (id) ON DELETE RESTRICT,
    CONSTRAINT fk_renewal_old_slot FOREIGN KEY (old_slot_id)
        REFERENCES parking_slot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_renewal_new_slot FOREIGN KEY (new_slot_id)
        REFERENCES parking_slot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_renewal_old_ticket_type FOREIGN KEY (old_ticket_type_id)
        REFERENCES ticket_type (id) ON DELETE RESTRICT,
    CONSTRAINT fk_renewal_new_ticket_type FOREIGN KEY (new_ticket_type_id)
        REFERENCES ticket_type (id) ON DELETE RESTRICT,
    CONSTRAINT fk_renewal_staff FOREIGN KEY (renewed_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT ck_renewal_time_extension CHECK (new_effective_to > old_effective_to),
    CONSTRAINT ck_renewal_price_nonnegative CHECK (
        additional_price >= 0 AND
        (old_price IS NULL OR old_price >= 0) AND
        (new_price IS NULL OR new_price >= 0)
    ),
    CONSTRAINT ck_renewal_row_version_positive CHECK (row_version >= 1)
);

CREATE INDEX idx_ticket_renewal_ticket_id ON ticket_renewal (ticket_id);
CREATE INDEX idx_ticket_renewal_created_at ON ticket_renewal (created_at);

COMMENT ON TABLE ticket_renewal IS 'Immutable financial and operational audit trail of ticket renewals ("Gia hạn vé" & "Lịch sử gia hạn" on Quản lý vé — Smart Mobility.png, TL-10, TL-15, OQ-58).';
COMMENT ON COLUMN ticket_renewal.id IS 'Primary key identifier of the renewal record.';
COMMENT ON COLUMN ticket_renewal.ticket_id IS 'Foreign key referencing the renewed ticket.';
COMMENT ON COLUMN ticket_renewal.old_slot_id IS 'Foreign key referencing parking_slot prior to renewal.';
COMMENT ON COLUMN ticket_renewal.new_slot_id IS 'Foreign key referencing parking_slot after renewal ("Đổi vị trí đỗ (tùy chọn)").';
COMMENT ON COLUMN ticket_renewal.old_ticket_type_id IS 'Foreign key referencing ticket_type prior to renewal (OQ-58).';
COMMENT ON COLUMN ticket_renewal.new_ticket_type_id IS 'Foreign key referencing newly selected ticket_type ("Loại vé gia hạn", OQ-58).';
COMMENT ON COLUMN ticket_renewal.old_price IS 'Ticket price prior to renewal (OQ-58).';
COMMENT ON COLUMN ticket_renewal.new_price IS 'New ticket tariff price upon renewal (OQ-58).';
COMMENT ON COLUMN ticket_renewal.old_effective_to IS 'Previous expiration timestamp before renewal ("Hạn hiện tại").';
COMMENT ON COLUMN ticket_renewal.new_effective_to IS 'Extended expiration timestamp after renewal ("Ngày kết thúc mới").';
COMMENT ON COLUMN ticket_renewal.additional_price IS 'Renewal fee charged for the extension ("Giá gia hạn").';
COMMENT ON COLUMN ticket_renewal.notes IS 'Optional renewal note ("Ghi chú gia hạn" on Dialog 2 Gia hạn vé, TL-10).';
COMMENT ON COLUMN ticket_renewal.renewed_by IS 'Optional foreign key referencing the employee who processed the renewal.';
COMMENT ON COLUMN ticket_renewal.created_at IS 'Timestamp when the renewal transaction occurred.';
COMMENT ON COLUMN ticket_renewal.row_version IS 'Concurrency version counter.';

-- =============================================================================
-- SECTION 6: GATES, ENTRY/EXIT SESSIONS & PAYMENTS (TL-05, TL-06, TL-07, TL-15)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 6.1. Table: parking_gate
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("4 Cổng quét tự động",
--         "Cổng vào 1", "Cổng vào 2", "Cổng ra 1", "Cổng ra 2", "Camera cổng ra 1"), TL-06
-- -----------------------------------------------------------------------------
CREATE TABLE parking_gate (
    id BIGSERIAL,
    lot_id BIGINT NOT NULL,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(50) NOT NULL,
    direction VARCHAR(10) NOT NULL,
    camera_status VARCHAR(20) NOT NULL DEFAULT 'ONLINE',
    is_auto_scan BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_parking_gate PRIMARY KEY (id),
    CONSTRAINT fk_parking_gate_lot FOREIGN KEY (lot_id)
        REFERENCES parking_lot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_parking_gate_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_gate_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_gate_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT ck_gate_direction_enum CHECK (direction IN ('IN', 'OUT')),
    CONSTRAINT ck_gate_camera_status_enum CHECK (
        camera_status IN ('ONLINE', 'LOW_LIGHT', 'DEGRADED', 'OFFLINE')
    ),
    CONSTRAINT ck_gate_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_gate_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_parking_gate_lot_code_active
    ON parking_gate (lot_id, code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_parking_gate_lot_name_active
    ON parking_gate (lot_id, name)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE parking_gate IS 'Entry and exit barrier gates with camera health and AI auto-scan status ("4 Cổng quét tự động", "Cổng vào 1", "Camera cổng ra 1" on Trang chủ, TL-06).';
COMMENT ON COLUMN parking_gate.id IS 'Primary key identifier of the parking gate.';
COMMENT ON COLUMN parking_gate.lot_id IS 'Foreign key referencing parent parking_lot.';
COMMENT ON COLUMN parking_gate.code IS 'Unique gate code within the parking lot (e.g., IN_01, OUT_01).';
COMMENT ON COLUMN parking_gate.name IS 'Display name of the gate (e.g., Cổng vào 1, Cổng ra 1; TL-06).';
COMMENT ON COLUMN parking_gate.direction IS 'Gate traffic direction: IN (entry) or OUT (exit) (TL-06).';
COMMENT ON COLUMN parking_gate.camera_status IS 'Operational health of the gate ALPR camera: ONLINE, LOW_LIGHT, DEGRADED, or OFFLINE (TL-06, OQ-81).';
COMMENT ON COLUMN parking_gate.is_auto_scan IS 'Whether automatic AI license plate scanning is enabled on this gate ("4 Cổng quét tự động", TL-06).';
COMMENT ON COLUMN parking_gate.is_active IS 'Whether the gate is currently active in operation.';
COMMENT ON COLUMN parking_gate.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN parking_gate.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN parking_gate.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN parking_gate.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN parking_gate.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 6.2. Table: vehicle_entry_exit_log
-- Source: Frontend `Lịch sử ra/vào — Smart Mobility.png` ("Mã phiên đỗ xe", "Cước phí",
--         "Hình ảnh đối soát") & `Trang chủ — Smart Mobility.png` ("Xem ảnh (99%)",
--         "Ảnh khớp", "Cần duyệt", "Nhập thủ công: 1.6%"), TL-05, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE vehicle_entry_exit_log (
    id BIGSERIAL,
    session_code VARCHAR(30) NOT NULL,
    vehicle_id BIGINT NULL,
    slot_id BIGINT NULL,
    ticket_id BIGINT NULL,
    reservation_id BIGINT NULL,
    entry_gate_id BIGINT NULL,
    exit_gate_id BIGINT NULL,
    license_plate VARCHAR(20) NOT NULL,
    license_plate_norm VARCHAR(20) GENERATED ALWAYS AS (fn_normalize_license_plate(license_plate)) STORED,
    ai_confidence NUMERIC(5, 2) NULL,
    recognition_source VARCHAR(20) NOT NULL DEFAULT 'AI',
    review_status VARCHAR(20) NOT NULL DEFAULT 'AUTO',
    fee_amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
    entry_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    exit_time TIMESTAMPTZ NULL,
    entry_image_url TEXT NULL,
    exit_image_url TEXT NULL,
    entry_handled_by BIGINT NULL,
    exit_handled_by BIGINT NULL,
    notes TEXT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_vehicle_entry_exit_log PRIMARY KEY (id),
    CONSTRAINT uq_log_session_code UNIQUE (session_code),
    CONSTRAINT fk_log_vehicle FOREIGN KEY (vehicle_id)
        REFERENCES vehicle (id) ON DELETE RESTRICT,
    CONSTRAINT fk_log_slot FOREIGN KEY (slot_id)
        REFERENCES parking_slot (id) ON DELETE RESTRICT,
    CONSTRAINT fk_log_ticket FOREIGN KEY (ticket_id)
        REFERENCES ticket (id) ON DELETE RESTRICT,
    CONSTRAINT fk_log_reservation FOREIGN KEY (reservation_id)
        REFERENCES slot_reservation (id) ON DELETE RESTRICT,
    CONSTRAINT fk_log_entry_gate FOREIGN KEY (entry_gate_id)
        REFERENCES parking_gate (id) ON DELETE RESTRICT,
    CONSTRAINT fk_log_exit_gate FOREIGN KEY (exit_gate_id)
        REFERENCES parking_gate (id) ON DELETE RESTRICT,
    CONSTRAINT fk_log_entry_staff FOREIGN KEY (entry_handled_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT fk_log_exit_staff FOREIGN KEY (exit_handled_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT ck_log_session_code_nonempty CHECK (btrim(session_code) <> ''),
    CONSTRAINT ck_log_license_plate_nonempty CHECK (btrim(license_plate) <> ''),
    CONSTRAINT ck_log_license_plate_format CHECK (license_plate ~ '^[A-Za-z0-9 .\-]+$'),
    CONSTRAINT ck_log_license_plate_norm_nonempty CHECK (license_plate_norm <> ''),
    CONSTRAINT ck_log_ai_confidence_range CHECK (
        ai_confidence IS NULL OR (ai_confidence >= 0 AND ai_confidence <= 100)
    ),
    CONSTRAINT ck_log_recognition_source_enum CHECK (
        recognition_source IN ('AI', 'MANUAL')
    ),
    CONSTRAINT ck_log_review_status_enum CHECK (
        review_status IN ('AUTO', 'MATCHED', 'NEEDS_REVIEW', 'APPROVED', 'REJECTED')
    ),
    CONSTRAINT ck_log_fee_nonnegative CHECK (fee_amount >= 0),
    CONSTRAINT ck_log_exit_after_entry CHECK (exit_time IS NULL OR exit_time >= entry_time),
    CONSTRAINT ck_log_row_version_positive CHECK (row_version >= 1)
);

CREATE UNIQUE INDEX uq_log_open_session_slot
    ON vehicle_entry_exit_log (slot_id)
    WHERE exit_time IS NULL AND slot_id IS NOT NULL;

CREATE UNIQUE INDEX uq_log_open_session_vehicle
    ON vehicle_entry_exit_log (vehicle_id)
    WHERE exit_time IS NULL AND vehicle_id IS NOT NULL;

CREATE UNIQUE INDEX uq_log_open_session_plate
    ON vehicle_entry_exit_log (license_plate_norm)
    WHERE exit_time IS NULL;

CREATE UNIQUE INDEX uq_log_reservation_session
    ON vehicle_entry_exit_log (reservation_id)
    WHERE reservation_id IS NOT NULL;

CREATE INDEX idx_log_vehicle_id ON vehicle_entry_exit_log (vehicle_id);
CREATE INDEX idx_log_slot_id ON vehicle_entry_exit_log (slot_id);
CREATE INDEX idx_entry_exit_ticket_id ON vehicle_entry_exit_log (ticket_id);
CREATE INDEX idx_entry_exit_gates ON vehicle_entry_exit_log (entry_gate_id, exit_gate_id);
CREATE INDEX idx_entry_exit_exit_gate_id ON vehicle_entry_exit_log (exit_gate_id);
CREATE INDEX idx_log_entry_time ON vehicle_entry_exit_log (entry_time);
CREATE INDEX idx_log_exit_time ON vehicle_entry_exit_log (exit_time);
CREATE INDEX idx_log_license_plate ON vehicle_entry_exit_log (license_plate_norm);
CREATE INDEX idx_log_review_status ON vehicle_entry_exit_log (review_status, entry_time DESC);
CREATE INDEX idx_log_license_plate_trgm ON vehicle_entry_exit_log USING gin (license_plate_norm gin_trgm_ops);
CREATE INDEX idx_log_session_code_trgm ON vehicle_entry_exit_log USING gin (session_code gin_trgm_ops);

COMMENT ON TABLE vehicle_entry_exit_log IS 'Barrier entry/exit parking sessions supporting both registered vehicles and unregistered visitors (vehicle_id NULL), with session_code, entry/exit gates, AI confidence, recognition source, review status, and fee amount (Lịch sử ra/vào & Trang chủ, TL-05, TL-15).';
COMMENT ON COLUMN vehicle_entry_exit_log.id IS 'Primary key identifier of the parking session log.';
COMMENT ON COLUMN vehicle_entry_exit_log.session_code IS 'Unique parking session code ("Mã phiên đỗ xe", e.g., #PK-20260414-01; TL-05).';
COMMENT ON COLUMN vehicle_entry_exit_log.vehicle_id IS 'Optional foreign key referencing registered vehicle; NULL for unregistered visitor vehicles (TL-05).';
COMMENT ON COLUMN vehicle_entry_exit_log.slot_id IS 'Optional foreign key referencing occupied physical parking_slot.';
COMMENT ON COLUMN vehicle_entry_exit_log.ticket_id IS 'Optional foreign key referencing subscription ticket applied to the session.';
COMMENT ON COLUMN vehicle_entry_exit_log.reservation_id IS 'Optional foreign key referencing advance slot_reservation fulfilled by this session (R1.5).';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_gate_id IS 'Optional foreign key referencing entry parking_gate ("Cổng vào 1/2", TL-05, TL-06).';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_gate_id IS 'Optional foreign key referencing exit parking_gate ("Cổng ra 1/2", TL-05, TL-06).';
COMMENT ON COLUMN vehicle_entry_exit_log.license_plate IS 'Raw license plate captured or entered at barrier gate.';
COMMENT ON COLUMN vehicle_entry_exit_log.license_plate_norm IS 'Canonical normalized license plate computed via fn_normalize_license_plate(license_plate) (TL-05, TL-15, OQ-75).';
COMMENT ON COLUMN vehicle_entry_exit_log.ai_confidence IS 'ALPR recognition confidence percentage 0..100 ("Xem ảnh (99%)", "84%", TL-05).';
COMMENT ON COLUMN vehicle_entry_exit_log.recognition_source IS 'Plate capture source: AI (automatic camera OCR) or MANUAL ("Nhập thủ công", TL-05).';
COMMENT ON COLUMN vehicle_entry_exit_log.review_status IS 'Verification status: AUTO, MATCHED ("Ảnh khớp"), NEEDS_REVIEW ("Cần duyệt"), APPROVED, or REJECTED (TL-05, OQ-81).';
COMMENT ON COLUMN vehicle_entry_exit_log.fee_amount IS 'Session parking fee in VND ("Cước phí" / "Cước phí tạm tính", TL-05, TL-07, OQ-80).';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_time IS 'Check-in timestamp when vehicle entered the parking lot ("Thời gian vào").';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_time IS 'Check-out timestamp when vehicle exited the parking lot ("Thời gian ra"); NULL while parked.';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_image_url IS 'Check-in comparison camera snapshot URI ("Ảnh lúc vào" under Hình ảnh đối soát, TL-05, OQ-60).';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_image_url IS 'Check-out comparison camera snapshot URI ("Ảnh lúc ra" under Hình ảnh đối soát, TL-05, OQ-60).';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_handled_by IS 'Optional foreign key referencing employee on duty at entry.';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_handled_by IS 'Optional foreign key referencing employee on duty at exit.';
COMMENT ON COLUMN vehicle_entry_exit_log.notes IS 'Optional operator notes for the session.';
COMMENT ON COLUMN vehicle_entry_exit_log.row_version IS 'Concurrency version counter.';
COMMENT ON COLUMN vehicle_entry_exit_log.created_at IS 'Log record creation timestamp.';

-- -----------------------------------------------------------------------------
-- 6.3. Table: payment
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("Doanh thu hôm nay",
--         "Tiền mặt: 18% | QR: 82%"), `Main Page.png` ("VietQR"), `Quản lý vé`
--         ("Giá vé", "Giá gia hạn"), `Lịch sử ra/vào` ("Cước phí"), TL-07
-- -----------------------------------------------------------------------------
CREATE TABLE payment (
    id BIGSERIAL,
    code VARCHAR(30) NOT NULL,
    amount NUMERIC(12, 2) NOT NULL,
    method VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'UNPAID',
    paid_at TIMESTAMPTZ NULL,
    received_by BIGINT NULL,
    provider_ref VARCHAR(100) NULL,
    session_id BIGINT NULL,
    ticket_id BIGINT NULL,
    renewal_id BIGINT NULL,
    reservation_id BIGINT NULL,
    notes TEXT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_payment PRIMARY KEY (id),
    CONSTRAINT fk_payment_received_by FOREIGN KEY (received_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT fk_payment_session FOREIGN KEY (session_id)
        REFERENCES vehicle_entry_exit_log (id) ON DELETE RESTRICT,
    CONSTRAINT fk_payment_ticket FOREIGN KEY (ticket_id)
        REFERENCES ticket (id) ON DELETE RESTRICT,
    CONSTRAINT fk_payment_renewal FOREIGN KEY (renewal_id)
        REFERENCES ticket_renewal (id) ON DELETE RESTRICT,
    CONSTRAINT fk_payment_reservation FOREIGN KEY (reservation_id)
        REFERENCES slot_reservation (id) ON DELETE RESTRICT,
    CONSTRAINT fk_payment_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_payment_code_nonempty CHECK (btrim(code) <> ''),
    CONSTRAINT ck_payment_amount_nonnegative CHECK (amount >= 0),
    CONSTRAINT ck_payment_method_enum CHECK (method IN ('CASH', 'VIETQR')),
    CONSTRAINT ck_payment_status_enum CHECK (
        status IN ('UNPAID', 'PAID', 'CANCELLED', 'REFUNDED')
    ),
    CONSTRAINT ck_payment_paid_timestamp CHECK (
        status NOT IN ('PAID', 'REFUNDED') OR paid_at IS NOT NULL
    ),
    CONSTRAINT ck_payment_single_target CHECK (
        num_nonnulls(session_id, ticket_id, renewal_id, reservation_id) = 1
    ),
    CONSTRAINT ck_payment_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_payment_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_payment_code_active
    ON payment (code)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_payment_session_id ON payment (session_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_payment_ticket_id ON payment (ticket_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_payment_renewal_id ON payment (renewal_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_payment_reservation_id ON payment (reservation_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_payment_paid_at_method ON payment (paid_at, method) WHERE deleted_at IS NULL AND status = 'PAID';
CREATE INDEX idx_payment_revenue_today ON payment ((COALESCE(paid_at, created_at))) WHERE deleted_at IS NULL AND status = 'PAID';

COMMENT ON TABLE payment IS 'Unified financial payment transactions supporting CASH and VIETQR methods and targeting exactly one session, ticket, renewal, or reservation (Trang chủ, Main Page, Quản lý vé, Lịch sử ra/vào, TL-07, R1.4).';
COMMENT ON COLUMN payment.id IS 'Primary key identifier of the payment record.';
COMMENT ON COLUMN payment.code IS 'Unique payment transaction code among active records.';
COMMENT ON COLUMN payment.amount IS 'Payment amount in VND (NUMERIC(12,2), must be >= 0).';
COMMENT ON COLUMN payment.method IS 'Payment method: CASH ("Tiền mặt") or VIETQR ("QR" / "VietQR") (TL-07).';
COMMENT ON COLUMN payment.status IS 'Payment lifecycle status: UNPAID, PAID, CANCELLED, or REFUNDED (TL-07, OQ-81).';
COMMENT ON COLUMN payment.paid_at IS 'Timestamp when payment was settled; NULL while UNPAID.';
COMMENT ON COLUMN payment.received_by IS 'Optional foreign key referencing cashier/operator employee.';
COMMENT ON COLUMN payment.provider_ref IS 'Optional external payment reference or VietQR transfer narrative (TL-07, OQ-82).';
COMMENT ON COLUMN payment.session_id IS 'Optional foreign key referencing vehicle_entry_exit_log (exactly one target must be non-null per ck_payment_single_target).';
COMMENT ON COLUMN payment.ticket_id IS 'Optional foreign key referencing ticket (initial ticket purchase target).';
COMMENT ON COLUMN payment.renewal_id IS 'Optional foreign key referencing ticket_renewal (ticket renewal target).';
COMMENT ON COLUMN payment.reservation_id IS 'Optional foreign key referencing slot_reservation (advance deposit target, R1.4).';
COMMENT ON COLUMN payment.notes IS 'Optional payment notes.';
COMMENT ON COLUMN payment.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN payment.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN payment.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN payment.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN payment.deleted_by IS 'Account that performed soft deletion.';

-- =============================================================================
-- SECTION 7: ACTIVITY FEED, ALERTS, NEWS & NOTIFICATIONS (TL-12, TL-13, TL-15)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 7.1. Table: activity_log
-- Source: Frontend `Sơ đồ bãi đậu xe — Smart Mobility.png` ("Hoạt động gần đây"), TL-12
-- -----------------------------------------------------------------------------
CREATE TABLE activity_log (
    id BIGSERIAL,
    actor_account_id BIGINT NULL,
    action VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id BIGINT NULL,
    message TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_activity_log PRIMARY KEY (id),
    CONSTRAINT fk_activity_log_actor FOREIGN KEY (actor_account_id)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_activity_log_action_nonempty CHECK (btrim(action) <> ''),
    CONSTRAINT ck_activity_log_entity_type_nonempty CHECK (btrim(entity_type) <> ''),
    CONSTRAINT ck_activity_log_message_nonempty CHECK (btrim(message) <> '')
);

CREATE INDEX idx_activity_log_occurred_at ON activity_log (occurred_at DESC);
CREATE INDEX idx_activity_log_entity ON activity_log (entity_type, entity_id);

COMMENT ON TABLE activity_log IS 'Append-only operational activity feed ("Hoạt động gần đây" on Sơ đồ bãi đậu xe — Smart Mobility.png, TL-12).';
COMMENT ON COLUMN activity_log.id IS 'Primary key identifier of the activity log entry.';
COMMENT ON COLUMN activity_log.actor_account_id IS 'Optional foreign key referencing the account that performed the action (NULL for automated gate/system events).';
COMMENT ON COLUMN activity_log.action IS 'Action code (e.g., SLOT_CHECKIN, SLOT_RESERVE, SLOT_MAINTENANCE, SLOT_CREATE).';
COMMENT ON COLUMN activity_log.entity_type IS 'Target domain entity type (e.g., PARKING_SLOT, VEHICLE_SESSION, TICKET).';
COMMENT ON COLUMN activity_log.entity_id IS 'Optional identifier of the affected domain record.';
COMMENT ON COLUMN activity_log.message IS 'Human-readable Vietnamese activity description displayed in "Hoạt động gần đây".';
COMMENT ON COLUMN activity_log.occurred_at IS 'Timestamp when the activity occurred.';

-- -----------------------------------------------------------------------------
-- 7.2. Table: system_alert
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("Cảnh báo bất thường & khẩn cấp":
--         Blacklist plate, Overstay 36h, Low-light camera quality), TL-13
-- -----------------------------------------------------------------------------
CREATE TABLE system_alert (
    id BIGSERIAL,
    alert_type VARCHAR(30) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    entity_type VARCHAR(50) NULL,
    entity_id BIGINT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ NULL,
    resolved_by BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_system_alert PRIMARY KEY (id),
    CONSTRAINT fk_system_alert_resolved_by FOREIGN KEY (resolved_by)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT ck_alert_type_enum CHECK (
        alert_type IN ('BLACKLIST_PLATE', 'OVERSTAY', 'CAMERA_QUALITY', 'SYSTEM')
    ),
    CONSTRAINT ck_alert_severity_enum CHECK (
        severity IN ('INFO', 'WARNING', 'CRITICAL')
    ),
    CONSTRAINT ck_alert_message_nonempty CHECK (btrim(message) <> ''),
    CONSTRAINT ck_alert_resolution_order CHECK (
        resolved_at IS NULL OR resolved_at >= occurred_at
    )
);

CREATE INDEX idx_system_alert_unresolved
    ON system_alert (occurred_at DESC)
    WHERE resolved_at IS NULL;

COMMENT ON TABLE system_alert IS 'Operational and security anomaly alerts ("Cảnh báo bất thường & khẩn cấp" on Trang chủ — Smart Mobility.png, TL-13).';
COMMENT ON COLUMN system_alert.id IS 'Primary key identifier of the system alert.';
COMMENT ON COLUMN system_alert.alert_type IS 'Alert category: BLACKLIST_PLATE, OVERSTAY, CAMERA_QUALITY, or SYSTEM (TL-13, OQ-81).';
COMMENT ON COLUMN system_alert.severity IS 'Alert severity level: INFO, WARNING, or CRITICAL (TL-13, OQ-81).';
COMMENT ON COLUMN system_alert.message IS 'Alert message text displayed on the dashboard.';
COMMENT ON COLUMN system_alert.entity_type IS 'Optional domain entity type associated with the alert (e.g., PLATE_BLACKLIST, VEHICLE_SESSION, PARKING_GATE).';
COMMENT ON COLUMN system_alert.entity_id IS 'Optional primary key of the associated domain entity.';
COMMENT ON COLUMN system_alert.occurred_at IS 'Timestamp when the anomaly or alert was triggered.';
COMMENT ON COLUMN system_alert.resolved_at IS 'Timestamp when the alert was acknowledged/resolved; NULL while unresolved ("cần xử lý").';
COMMENT ON COLUMN system_alert.resolved_by IS 'Optional foreign key referencing the employee who resolved the alert.';
COMMENT ON COLUMN system_alert.created_at IS 'Record creation timestamp.';

-- -----------------------------------------------------------------------------
-- 7.3. Table: news
-- Source: Sprint Plan `Tasks_Sprint_1` (SCO-03), OQ-51, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE news (
    id BIGSERIAL,
    title VARCHAR(200) NOT NULL,
    slug VARCHAR(220) NOT NULL,
    summary VARCHAR(500) NULL,
    content TEXT NOT NULL,
    thumbnail_url TEXT NULL,
    author_id BIGINT NOT NULL,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    published_at TIMESTAMPTZ NULL,
    view_count INTEGER NOT NULL DEFAULT 0,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_news PRIMARY KEY (id),
    CONSTRAINT fk_news_author FOREIGN KEY (author_id)
        REFERENCES employee (id) ON DELETE RESTRICT,
    CONSTRAINT fk_news_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_news_title_nonempty CHECK (btrim(title) <> ''),
    CONSTRAINT ck_news_slug_format CHECK (slug ~ '^[a-z0-9-]+$'),
    CONSTRAINT ck_news_content_nonempty CHECK (btrim(content) <> ''),
    CONSTRAINT ck_news_view_count_nonnegative CHECK (view_count >= 0),
    CONSTRAINT ck_news_row_version_positive CHECK (row_version >= 1),
    CONSTRAINT ck_news_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_news_slug_active
    ON news (slug)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_news_published
    ON news (published_at DESC)
    WHERE deleted_at IS NULL AND is_published = TRUE;

CREATE INDEX idx_news_author_id ON news (author_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE news IS 'Parking facility news and announcements article table (SCO-03, OQ-51, TL-15).';
COMMENT ON COLUMN news.id IS 'Primary key identifier of the news article.';
COMMENT ON COLUMN news.title IS 'Headline title of the news article.';
COMMENT ON COLUMN news.slug IS 'URL-safe lowercase slug unique among active articles.';
COMMENT ON COLUMN news.summary IS 'Optional short summary excerpt.';
COMMENT ON COLUMN news.content IS 'Full article body content.';
COMMENT ON COLUMN news.thumbnail_url IS 'Optional cover thumbnail image URL.';
COMMENT ON COLUMN news.author_id IS 'Foreign key referencing authoring employee.';
COMMENT ON COLUMN news.is_published IS 'Publication visibility flag.';
COMMENT ON COLUMN news.published_at IS 'Publication timestamp.';
COMMENT ON COLUMN news.view_count IS 'Article read counter (must be >= 0).';
COMMENT ON COLUMN news.row_version IS 'Optimistic concurrency control version counter (TL-15, OQ-64).';
COMMENT ON COLUMN news.created_at IS 'Record creation timestamp.';
COMMENT ON COLUMN news.updated_at IS 'Record last update timestamp.';
COMMENT ON COLUMN news.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN news.deleted_by IS 'Account that performed soft deletion.';

-- -----------------------------------------------------------------------------
-- 7.4. Table: notification
-- Source: SRS 4.2 (`Bảng thông báo`), OQ-51, TL-15
-- -----------------------------------------------------------------------------
CREATE TABLE notification (
    id BIGSERIAL,
    recipient_account_id BIGINT NULL,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    notification_type VARCHAR(30) NOT NULL DEFAULT 'SYSTEM',
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,
    deleted_by BIGINT NULL,
    CONSTRAINT pk_notification PRIMARY KEY (id),
    CONSTRAINT fk_notification_recipient FOREIGN KEY (recipient_account_id)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT fk_notification_deleted_by FOREIGN KEY (deleted_by)
        REFERENCES account (id) ON DELETE RESTRICT,
    CONSTRAINT ck_notification_title_nonempty CHECK (btrim(title) <> ''),
    CONSTRAINT ck_notification_content_nonempty CHECK (btrim(content) <> ''),
    CONSTRAINT ck_notification_type_enum CHECK (
        notification_type IN ('SYSTEM', 'TICKET_EXPIRY', 'PAYMENT', 'SECURITY')
    ),
    CONSTRAINT ck_notification_read_pair CHECK (
        (is_read = FALSE AND read_at IS NULL) OR (is_read = TRUE AND read_at IS NOT NULL)
    ),
    CONSTRAINT ck_notification_soft_delete_pair CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL) OR (deleted_at IS NOT NULL)
    )
);

CREATE INDEX idx_notification_recipient_unread
    ON notification (recipient_account_id, is_read)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE notification IS 'User and broadcast notification messages table (SRS 4.2, OQ-51, TL-15).';
COMMENT ON COLUMN notification.id IS 'Primary key identifier of the notification.';
COMMENT ON COLUMN notification.recipient_account_id IS 'Optional target account; NULL indicates system-wide broadcast.';
COMMENT ON COLUMN notification.title IS 'Short notification title.';
COMMENT ON COLUMN notification.content IS 'Notification body content.';
COMMENT ON COLUMN notification.notification_type IS 'Notification category: SYSTEM, TICKET_EXPIRY, PAYMENT, or SECURITY.';
COMMENT ON COLUMN notification.is_read IS 'Whether the recipient has read the notification.';
COMMENT ON COLUMN notification.read_at IS 'Timestamp when the notification was marked read.';
COMMENT ON COLUMN notification.created_at IS 'Notification creation timestamp.';
COMMENT ON COLUMN notification.deleted_at IS 'Soft deletion timestamp (ADR-0003).';
COMMENT ON COLUMN notification.deleted_by IS 'Account that performed soft deletion.';

-- =============================================================================
-- SECTION 8: ANALYTICAL & DASHBOARD VIEWS (TL-14, TL-15, TL-27, SRS 4.7)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 8.1. View: v_slot_occupancy_by_floor
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("Tình trạng chỗ đỗ theo khu vực") &
--         `Sơ đồ bãi đậu xe — Smart Mobility.png` (6 KPI cards + floor/zone tabs), TL-14, TL-27
-- -----------------------------------------------------------------------------
CREATE VIEW v_slot_occupancy_by_floor AS
WITH open_sessions AS (
    SELECT DISTINCT l.slot_id
    FROM vehicle_entry_exit_log l
    LEFT JOIN vehicle v ON v.id = l.vehicle_id
    LEFT JOIN customer c ON c.id = v.customer_id
    WHERE l.exit_time IS NULL
      AND l.slot_id IS NOT NULL
      AND (l.vehicle_id IS NULL OR (v.deleted_at IS NULL AND c.deleted_at IS NULL))
),
active_tickets AS (
    SELECT DISTINCT t.slot_id
    FROM ticket t
    JOIN vehicle v ON v.id = t.vehicle_id AND v.deleted_at IS NULL
    JOIN customer c ON c.id = t.customer_id AND c.deleted_at IS NULL
    WHERE t.deleted_at IS NULL
      AND t.status IN ('ACTIVE', 'RENEWING')
      AND CURRENT_TIMESTAMP >= t.effective_from
      AND CURRENT_TIMESTAMP < t.effective_to
),
active_reservations AS (
    SELECT DISTINCT r.slot_id
    FROM slot_reservation r
    LEFT JOIN vehicle v ON v.id = r.vehicle_id
    LEFT JOIN customer c ON c.id = r.customer_id
    WHERE r.deleted_at IS NULL
      AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED')
      AND CURRENT_TIMESTAMP < r.reserved_until
      AND (r.vehicle_id IS NULL OR v.deleted_at IS NULL)
      AND (r.customer_id IS NULL OR c.deleted_at IS NULL)
),
slot_states AS (
    SELECT
        pl.id AS lot_id,
        pl.code AS lot_code,
        pl.name AS lot_name,
        pf.id AS floor_id,
        pf.code AS floor_code,
        pf.name AS floor_name,
        pz.id AS zone_id,
        pz.code AS zone_code,
        pz.name AS zone_name,
        ps.id AS slot_id,
        ps.status AS stored_status,
        CASE
            WHEN ps.status = 'MAINTENANCE' THEN 'MAINTENANCE'
            WHEN ps.status = 'CHARGING' THEN 'CHARGING'
            WHEN os.slot_id IS NOT NULL OR ps.status = 'OCCUPIED' THEN 'OCCUPIED'
            WHEN at.slot_id IS NOT NULL OR ar.slot_id IS NOT NULL OR ps.status = 'RESERVED' THEN 'RESERVED'
            ELSE 'AVAILABLE'
        END AS effective_status
    FROM parking_lot pl
    JOIN parking_floor pf ON pf.lot_id = pl.id AND pf.deleted_at IS NULL
    JOIN parking_zone pz ON pz.floor_id = pf.id AND pz.deleted_at IS NULL
    LEFT JOIN parking_slot ps ON ps.zone_id = pz.id AND ps.deleted_at IS NULL
    LEFT JOIN open_sessions os ON os.slot_id = ps.id
    LEFT JOIN active_tickets at ON at.slot_id = ps.id
    LEFT JOIN active_reservations ar ON ar.slot_id = ps.id
    WHERE pl.deleted_at IS NULL
)
SELECT
    lot_id,
    lot_code,
    lot_name,
    floor_id,
    floor_code,
    floor_name,
    zone_id,
    zone_code,
    zone_name,
    COUNT(slot_id)::BIGINT AS total_slots,
    COUNT(slot_id) FILTER (WHERE effective_status <> 'MAINTENANCE')::BIGINT AS operational_slots,
    COUNT(slot_id) FILTER (WHERE effective_status = 'AVAILABLE')::BIGINT AS available_slots,
    COUNT(slot_id) FILTER (WHERE effective_status = 'OCCUPIED')::BIGINT AS occupied_slots,
    COUNT(slot_id) FILTER (WHERE effective_status = 'RESERVED')::BIGINT AS reserved_slots,
    COUNT(slot_id) FILTER (WHERE effective_status = 'CHARGING')::BIGINT AS charging_slots,
    COUNT(slot_id) FILTER (WHERE effective_status = 'MAINTENANCE')::BIGINT AS maintenance_slots,
    COALESCE(
        ROUND(
            (COUNT(slot_id) FILTER (WHERE effective_status IN ('OCCUPIED', 'RESERVED', 'CHARGING'))::NUMERIC
             / NULLIF(COUNT(slot_id) FILTER (WHERE effective_status <> 'MAINTENANCE'), 0)) * 100,
            2
        ),
        0.00
    ) AS occupancy_rate_pct
FROM slot_states
GROUP BY lot_id, lot_code, lot_name, floor_id, floor_code, floor_name, zone_id, zone_code, zone_name;

COMMENT ON VIEW v_slot_occupancy_by_floor IS 'Floor- and zone-level parking slot capacity and real-time occupancy breakdown for Trang chủ and Sơ đồ bãi đậu xe (TL-02, TL-03, TL-14, TL-27, OQ-63).';

-- -----------------------------------------------------------------------------
-- 8.2. View: v_revenue_today_by_method
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("Doanh thu hôm nay",
--         "Tiền mặt: 18% | QR: 82%"), TL-07, TL-14, TL-27
-- -----------------------------------------------------------------------------
CREATE VIEW v_revenue_today_by_method AS
WITH today_payments AS (
    SELECT
        p.method,
        p.amount
    FROM payment p
    LEFT JOIN ticket t ON t.id = p.ticket_id
    LEFT JOIN ticket_renewal tr ON tr.id = p.renewal_id
    LEFT JOIN ticket tr_t ON tr_t.id = tr.ticket_id
    LEFT JOIN slot_reservation sr ON sr.id = p.reservation_id
    WHERE p.deleted_at IS NULL
      AND p.status = 'PAID'
      AND COALESCE(p.paid_at, p.created_at)::DATE = CURRENT_DATE
      AND (p.ticket_id IS NULL OR t.deleted_at IS NULL)
      AND (p.renewal_id IS NULL OR tr_t.deleted_at IS NULL)
      AND (p.reservation_id IS NULL OR sr.deleted_at IS NULL)
)
SELECT
    CURRENT_DATE AS revenue_date,
    COALESCE(SUM(amount), 0.00)::NUMERIC(12, 2) AS total_revenue,
    COALESCE(SUM(amount) FILTER (WHERE method = 'CASH'), 0.00)::NUMERIC(12, 2) AS cash_revenue,
    COALESCE(SUM(amount) FILTER (WHERE method = 'VIETQR'), 0.00)::NUMERIC(12, 2) AS vietqr_revenue,
    COALESCE(
        ROUND((SUM(amount) FILTER (WHERE method = 'CASH') / NULLIF(SUM(amount), 0)) * 100, 2),
        0.00
    ) AS cash_pct,
    COALESCE(
        ROUND((SUM(amount) FILTER (WHERE method = 'VIETQR') / NULLIF(SUM(amount), 0)) * 100, 2),
        0.00
    ) AS vietqr_pct
FROM today_payments;

COMMENT ON VIEW v_revenue_today_by_method IS 'Dashboard KPI card view computing today revenue split by CASH ("Tiền mặt") and VIETQR ("QR") on Trang chủ — Smart Mobility.png (TL-07, TL-14, TL-27).';

-- -----------------------------------------------------------------------------
-- 8.3. View: v_traffic_by_hour
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("Lưu lượng xe vào / ra theo giờ"), TL-05, TL-14, TL-27
-- -----------------------------------------------------------------------------
CREATE VIEW v_traffic_by_hour AS
WITH active_sessions AS (
    SELECT
        l.entry_time,
        l.exit_time
    FROM vehicle_entry_exit_log l
    LEFT JOIN parking_slot ps ON ps.id = l.slot_id
    LEFT JOIN vehicle v ON v.id = l.vehicle_id
    LEFT JOIN customer c ON c.id = v.customer_id
    LEFT JOIN ticket t ON t.id = l.ticket_id
    WHERE (l.slot_id IS NULL OR ps.deleted_at IS NULL)
      AND (l.vehicle_id IS NULL OR (v.deleted_at IS NULL AND c.deleted_at IS NULL))
      AND (l.ticket_id IS NULL OR t.deleted_at IS NULL)
),
entry_hours AS (
    SELECT
        DATE_TRUNC('hour', entry_time) AS traffic_hour,
        COUNT(*)::BIGINT AS entry_count
    FROM active_sessions
    GROUP BY DATE_TRUNC('hour', entry_time)
),
exit_hours AS (
    SELECT
        DATE_TRUNC('hour', exit_time) AS traffic_hour,
        COUNT(*)::BIGINT AS exit_count
    FROM active_sessions
    WHERE exit_time IS NOT NULL
    GROUP BY DATE_TRUNC('hour', exit_time)
)
SELECT
    COALESCE(en.traffic_hour, ex.traffic_hour) AS traffic_hour,
    COALESCE(en.entry_count, 0)::BIGINT AS entry_count,
    COALESCE(ex.exit_count, 0)::BIGINT AS exit_count,
    (COALESCE(en.entry_count, 0) + COALESCE(ex.exit_count, 0))::BIGINT AS total_movements
FROM entry_hours en
FULL OUTER JOIN exit_hours ex ON en.traffic_hour = ex.traffic_hour
ORDER BY traffic_hour DESC;

COMMENT ON VIEW v_traffic_by_hour IS 'Hourly vehicle entry and exit traffic aggregation for the "Lưu lượng xe vào / ra theo giờ" chart on Trang chủ — Smart Mobility.png (TL-05, TL-14, TL-27).';

-- -----------------------------------------------------------------------------
-- 8.4. View: v_ai_recognition_stats
-- Source: Frontend `Trang chủ — Smart Mobility.png` ("Tỷ lệ nhận diện AI: 98.4%",
--         "Nhập thủ công: 1.6%", "4 Cổng quét tự động"), TL-05, TL-06, TL-14, TL-27
-- -----------------------------------------------------------------------------
CREATE VIEW v_ai_recognition_stats AS
SELECT
    COUNT(*)::BIGINT AS total_sessions,
    COUNT(*) FILTER (WHERE l.recognition_source = 'AI')::BIGINT AS ai_sessions,
    COUNT(*) FILTER (WHERE l.recognition_source = 'MANUAL')::BIGINT AS manual_sessions,
    COALESCE(
        ROUND((COUNT(*) FILTER (WHERE l.recognition_source = 'AI')::NUMERIC / NULLIF(COUNT(*), 0)) * 100, 2),
        0.00
    ) AS ai_recognition_rate_pct,
    COALESCE(
        ROUND((COUNT(*) FILTER (WHERE l.recognition_source = 'MANUAL')::NUMERIC / NULLIF(COUNT(*), 0)) * 100, 2),
        0.00
    ) AS manual_rate_pct,
    COALESCE(ROUND(AVG(l.ai_confidence), 2), 0.00) AS avg_ai_confidence,
    (
        SELECT COUNT(*)::BIGINT
        FROM parking_gate g
        JOIN parking_lot pl ON pl.id = g.lot_id AND pl.deleted_at IS NULL
        WHERE g.deleted_at IS NULL
          AND g.is_active = TRUE
          AND g.is_auto_scan = TRUE
    ) AS active_auto_scan_gates
FROM vehicle_entry_exit_log l
LEFT JOIN parking_slot ps ON ps.id = l.slot_id
LEFT JOIN vehicle v ON v.id = l.vehicle_id
LEFT JOIN customer c ON c.id = v.customer_id
LEFT JOIN ticket t ON t.id = l.ticket_id
WHERE (l.slot_id IS NULL OR ps.deleted_at IS NULL)
  AND (l.vehicle_id IS NULL OR (v.deleted_at IS NULL AND c.deleted_at IS NULL))
  AND (l.ticket_id IS NULL OR t.deleted_at IS NULL);

COMMENT ON VIEW v_ai_recognition_stats IS 'Dashboard KPI view computing AI vs manual plate recognition rates, average AI confidence, and active auto-scan gate count for Trang chủ — Smart Mobility.png (TL-05, TL-06, TL-14, TL-27).';

-- -----------------------------------------------------------------------------
-- 8.5. View: v_customer_status_summary
-- Source: Frontend `Khách hàng — Smart Mobility.png` ("Tổng khách hàng",
--         "Đang hoạt động", "Tạm ngừng", "Blacklist/Tạm khoá"), TL-08, TL-14, TL-27
-- -----------------------------------------------------------------------------
CREATE VIEW v_customer_status_summary AS
SELECT
    COUNT(*)::BIGINT AS total_customers,
    COUNT(*) FILTER (WHERE status = 'ACTIVE')::BIGINT AS active_customers,
    COUNT(*) FILTER (WHERE status = 'SUSPENDED')::BIGINT AS suspended_customers,
    COUNT(*) FILTER (WHERE status = 'BLACKLISTED')::BIGINT AS blacklisted_customers
FROM customer
WHERE deleted_at IS NULL;

COMMENT ON VIEW v_customer_status_summary IS 'Customer KPI summary cards by status (ACTIVE, SUSPENDED, BLACKLISTED) for Khách hàng — Smart Mobility.png (TL-08, TL-14, TL-27).';

-- -----------------------------------------------------------------------------
-- 8.6. View: v_revenue_statistics
-- Source: SRS 4.7.1 & TL-14, TL-27 (Monthly, quarterly, and annual revenue across active tickets and renewals)
-- -----------------------------------------------------------------------------
CREATE VIEW v_revenue_statistics AS
WITH financial_events AS (
    SELECT
        EXTRACT(YEAR FROM t.created_at)::INTEGER AS report_year,
        EXTRACT(QUARTER FROM t.created_at)::INTEGER AS report_quarter,
        EXTRACT(MONTH FROM t.created_at)::INTEGER AS report_month,
        1::BIGINT AS ticket_cnt,
        0::BIGINT AS renewal_cnt,
        t.price AS amount
    FROM ticket t
    JOIN customer c ON c.id = t.customer_id AND c.deleted_at IS NULL
    JOIN vehicle v ON v.id = t.vehicle_id AND v.deleted_at IS NULL
    JOIN parking_slot ps ON ps.id = t.slot_id AND ps.deleted_at IS NULL
    WHERE t.deleted_at IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM payment p
          WHERE p.ticket_id = t.id
            AND p.deleted_at IS NOT NULL
      )
    UNION ALL
    SELECT
        EXTRACT(YEAR FROM tr.created_at)::INTEGER AS report_year,
        EXTRACT(QUARTER FROM tr.created_at)::INTEGER AS report_quarter,
        EXTRACT(MONTH FROM tr.created_at)::INTEGER AS report_month,
        0::BIGINT AS ticket_cnt,
        1::BIGINT AS renewal_cnt,
        tr.additional_price AS amount
    FROM ticket_renewal tr
    JOIN ticket t ON t.id = tr.ticket_id AND t.deleted_at IS NULL
    JOIN customer c ON c.id = t.customer_id AND c.deleted_at IS NULL
    JOIN vehicle v ON v.id = t.vehicle_id AND v.deleted_at IS NULL
    JOIN parking_slot ps ON ps.id = t.slot_id AND ps.deleted_at IS NULL
    WHERE NOT EXISTS (
        SELECT 1
        FROM payment p
        WHERE p.renewal_id = tr.id
          AND p.deleted_at IS NOT NULL
    )
)
SELECT
    report_year,
    report_quarter,
    report_month,
    SUM(ticket_cnt)::BIGINT AS total_tickets_sold,
    SUM(renewal_cnt)::BIGINT AS total_renewals,
    COALESCE(SUM(amount), 0.00)::NUMERIC(12, 2) AS total_revenue
FROM financial_events
GROUP BY report_year, report_quarter, report_month
ORDER BY report_year DESC, report_quarter DESC, report_month DESC;

COMMENT ON VIEW v_revenue_statistics IS 'Monthly, quarterly, and annual financial revenue aggregation across active ticket sales and renewals excluding soft-deleted records (SRS 4.7.1, OQ-11, TL-14, TL-27).';

-- -----------------------------------------------------------------------------
-- 8.7. View: v_vehicle_traffic_daily
-- Source: SRS 4.7.2 & `Trang chủ — Smart Mobility.png` ("Lượt xe vào / ra hôm nay"), TL-14, TL-27
-- -----------------------------------------------------------------------------
CREATE VIEW v_vehicle_traffic_daily AS
WITH active_sessions AS (
    SELECT
        l.entry_time,
        l.exit_time
    FROM vehicle_entry_exit_log l
    LEFT JOIN parking_slot ps ON ps.id = l.slot_id
    LEFT JOIN vehicle v ON v.id = l.vehicle_id
    LEFT JOIN customer c ON c.id = v.customer_id
    LEFT JOIN ticket t ON t.id = l.ticket_id
    WHERE (l.slot_id IS NULL OR ps.deleted_at IS NULL)
      AND (l.vehicle_id IS NULL OR (v.deleted_at IS NULL AND c.deleted_at IS NULL))
      AND (l.ticket_id IS NULL OR t.deleted_at IS NULL)
),
entry_daily AS (
    SELECT
        entry_time::DATE AS traffic_date,
        COUNT(*)::BIGINT AS total_entries,
        COUNT(*) FILTER (WHERE exit_time IS NULL)::BIGINT AS currently_parked_count
    FROM active_sessions
    GROUP BY entry_time::DATE
),
exit_daily AS (
    SELECT
        exit_time::DATE AS traffic_date,
        COUNT(*)::BIGINT AS total_exits
    FROM active_sessions
    WHERE exit_time IS NOT NULL
    GROUP BY exit_time::DATE
)
SELECT
    COALESCE(en.traffic_date, ex.traffic_date) AS traffic_date,
    COALESCE(en.total_entries, 0)::BIGINT AS total_entries,
    COALESCE(ex.total_exits, 0)::BIGINT AS total_exits,
    COALESCE(en.currently_parked_count, 0)::BIGINT AS currently_parked_count
FROM entry_daily en
FULL OUTER JOIN exit_daily ex ON en.traffic_date = ex.traffic_date
ORDER BY traffic_date DESC;

COMMENT ON VIEW v_vehicle_traffic_daily IS 'Daily vehicle entry, exit, and currently parked counts for Trang chủ and SRS 4.7.2 excluding soft-deleted entities (TL-14, TL-27).';

-- -----------------------------------------------------------------------------
-- 8.8. View: v_customer_vehicle_summary
-- Source: SRS 4.7.2 & `Khách hàng` / `Quản lý xe`, TL-14, TL-27
-- -----------------------------------------------------------------------------
CREATE VIEW v_customer_vehicle_summary AS
WITH vehicle_counts AS (
    SELECT
        v.customer_id,
        COUNT(*)::BIGINT AS total_registered_vehicles
    FROM vehicle v
    JOIN vehicle_type vt ON vt.id = v.vehicle_type_id AND vt.deleted_at IS NULL
    WHERE v.deleted_at IS NULL
    GROUP BY v.customer_id
),
ticket_counts AS (
    SELECT
        t.customer_id,
        COUNT(*)::BIGINT AS total_active_tickets
    FROM ticket t
    JOIN vehicle v ON v.id = t.vehicle_id AND v.deleted_at IS NULL
    JOIN parking_slot ps ON ps.id = t.slot_id AND ps.deleted_at IS NULL
    WHERE t.deleted_at IS NULL
      AND t.status IN ('ACTIVE', 'RENEWING')
      AND t.effective_to > CURRENT_TIMESTAMP
    GROUP BY t.customer_id
)
SELECT
    c.id AS customer_id,
    c.code AS customer_code,
    c.full_name,
    c.phone,
    c.status AS customer_status,
    COALESCE(vc.total_registered_vehicles, 0)::BIGINT AS total_registered_vehicles,
    COALESCE(tc.total_active_tickets, 0)::BIGINT AS total_active_tickets
FROM customer c
LEFT JOIN vehicle_counts vc ON vc.customer_id = c.id
LEFT JOIN ticket_counts tc ON tc.customer_id = c.id
WHERE c.deleted_at IS NULL;

COMMENT ON VIEW v_customer_vehicle_summary IS 'Per-customer summary of registered vehicles and active tickets using pre-aggregated CTEs to prevent Cartesian duplication (SRS 4.7.2, TL-14, TL-27).';

-- =============================================================================
-- SECTION 9: ADVANCE SLOT BOOKING MANAGEMENT (Milestones M1, M2, M3)
-- Source: SRS 4.8 & Frontend Advance Slot Booking (R1.1, R1.2, R1.3, TL-04, TL-14)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 9.1. View: v_booking_overview
-- Comprehensive overview of advance slot reservations with customer, vehicle,
-- slot hierarchy, and deposit payment details.
-- -----------------------------------------------------------------------------
CREATE VIEW v_booking_overview AS
SELECT
    r.id AS reservation_id,
    r.code AS reservation_code,
    pl.id AS lot_id,
    pl.code AS lot_code,
    pl.name AS lot_name,
    pf.id AS floor_id,
    pf.code AS floor_code,
    pf.name AS floor_name,
    pz.id AS zone_id,
    pz.code AS zone_code,
    pz.name AS zone_name,
    ps.id AS slot_id,
    ps.code AS slot_code,
    ps.slot_kind,
    c.id AS customer_id,
    c.code AS customer_code,
    COALESCE(c.full_name, r.reserved_name) AS customer_name,
    COALESCE(c.phone, r.reserved_phone) AS customer_phone,
    v.id AS vehicle_id,
    v.license_plate,
    v.license_plate AS license_plate_raw,
    v.license_plate_norm,
    vt.name AS vehicle_type_name,
    r.booking_channel,
    r.reserved_from,
    r.reserved_until,
    r.status AS reservation_status,
    r.hold_expires_at,
    r.deposit_amount,
    p.id AS payment_id,
    p.code AS payment_code,
    p.status AS payment_status,
    p.method AS payment_method,
    r.checked_in_at,
    r.completed_at,
    r.cancelled_at,
    r.cancelled_by,
    r.cancel_reason,
    r.no_show_at,
    r.notes,
    r.row_version,
    r.created_at,
    r.updated_at
FROM slot_reservation r
JOIN parking_slot ps ON ps.id = r.slot_id AND ps.deleted_at IS NULL
JOIN parking_zone pz ON pz.id = ps.zone_id AND pz.deleted_at IS NULL
JOIN parking_floor pf ON pf.id = pz.floor_id AND pf.deleted_at IS NULL
JOIN parking_lot pl ON pl.id = pf.lot_id AND pl.deleted_at IS NULL
LEFT JOIN customer c ON c.id = r.customer_id AND c.deleted_at IS NULL
LEFT JOIN vehicle v ON v.id = r.vehicle_id AND v.deleted_at IS NULL
LEFT JOIN vehicle_type vt ON vt.id = v.vehicle_type_id AND vt.deleted_at IS NULL
LEFT JOIN payment p ON p.reservation_id = r.id AND p.deleted_at IS NULL
WHERE r.deleted_at IS NULL;

COMMENT ON VIEW v_booking_overview IS 'Comprehensive overview of advance slot reservations with customer, vehicle, slot hierarchy, and deposit payment details (R1.1, R1.2, R1.3, TL-04, TL-14).';

COMMIT;
