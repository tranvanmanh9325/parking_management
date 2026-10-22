-- =============================================================================
-- FILE: db/01-schema.sql
-- DỰ ÁN: Hệ thống quản lý bãi đỗ xe ô tô (parking_management)
-- CƠ SỞ DỮ LIỆU: PostgreSQL
-- MÔ TẢ:
--   Lược đồ cơ sở dữ liệu quan hệ của hệ thống quản lý bãi đỗ xe ô tô.
--   Quy ước chung: xoá mềm (deleted_at, deleted_by), khoá lạc quan (row_version)
--   và mọi khoá ngoại đều ON DELETE RESTRICT.
--   Tập lệnh chỉ tạo mới, không có câu lệnh phá huỷ dữ liệu.
--   PHẠM VI (giai đoạn thiết kế cơ sở dữ liệu): chỉ gồm bảng, ràng buộc, chỉ mục,
--   chú thích và các view thống kê. Trigger và hàm nghiệp vụ được lược bỏ ở giai
--   đoạn này; chỉ giữ fn_normalize_license_plate vì các cột sinh tự động phụ thuộc
--   vào hàm đó.
-- =============================================================================

BEGIN;

SET client_encoding = 'UTF8';

-- Cần cho ràng buộc loại trừ theo thời gian, kết hợp BIGINT với TSTZRANGE
CREATE EXTENSION btree_gist;

-- Cần cho chỉ mục GIN trigram (một phần) giúp tìm chuỗi con nhanh
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- =============================================================================
-- PHẦN 0: CÁC HÀM CHUẨN HOÁ DỮ LIỆU
-- =============================================================================

CREATE FUNCTION fn_normalize_license_plate(p_input TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE STRICT PARALLEL SAFE
SET search_path = public, pg_temp
AS $$
    SELECT UPPER(REGEXP_REPLACE(p_input, '[^A-Za-z0-9]', '', 'g'));
$$;

COMMENT ON FUNCTION fn_normalize_license_plate(TEXT) IS 'Chuẩn hoá biển số xe: bỏ ký tự phân cách (dấu chấm, gạch ngang, khoảng trắng) và đổi sang chữ hoa để so khớp và kiểm tra trùng biển số.';

-- =============================================================================
-- PHẦN 1: XÁC THỰC VÀ PHÂN QUYỀN
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1.1. Bảng: account
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

COMMENT ON TABLE account IS 'Lưu danh tính đăng nhập (email hoặc số điện thoại), băm mật khẩu và vai trò. Nhân viên và khách hàng liên kết với tài khoản qua cột account_id của bảng của họ. Tách tài khoản khỏi hồ sơ giúp một người có thể chưa có đăng nhập mà vẫn có hồ sơ.';
COMMENT ON COLUMN account.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN account.email IS 'Email đăng nhập; duy nhất không phân biệt hoa thường trong các tài khoản chưa xoá mềm.';
COMMENT ON COLUMN account.phone IS 'Số điện thoại đăng nhập (9-15 chữ số); duy nhất trong các tài khoản chưa xoá mềm. Phải có email hoặc phone.';
COMMENT ON COLUMN account.password_hash IS 'Chuỗi băm mật khẩu (Argon2id/PBKDF2). Không bao giờ lưu mật khẩu thô.';
COMMENT ON COLUMN account.role IS 'Vai trò phân quyền: MANAGER, EMPLOYEE hoặc CUSTOMER.';
COMMENT ON COLUMN account.is_active IS 'Cờ kích hoạt; FALSE tương ứng chức năng "Khoá tài khoản".';
COMMENT ON COLUMN account.last_login_at IS 'Thời điểm đăng nhập thành công gần nhất.';
COMMENT ON COLUMN account.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN account.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN account.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN account.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN account.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 1.2. Bảng: persistent_login_token
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

COMMENT ON TABLE persistent_login_token IS 'Kho token cho tính năng "Ghi nhớ đăng nhập" theo mẫu series/token: mỗi lần dùng, token được xoay vòng còn series giữ nguyên; token lạ cùng series báo hiệu bị đánh cắp. Chỉ lưu giá trị băm, không lưu token thô.';
COMMENT ON COLUMN persistent_login_token.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN persistent_login_token.series IS 'Mã chuỗi cố định qua các lần xoay token, dùng phát hiện đánh cắp; duy nhất.';
COMMENT ON COLUMN persistent_login_token.token_hash IS 'Băm SHA-256 của token ghi nhớ dùng một lần (token thô chỉ nằm trong cookie).';
COMMENT ON COLUMN persistent_login_token.account_id IS 'Tài khoản sở hữu (FK → account).';
COMMENT ON COLUMN persistent_login_token.ip_address IS 'IP lúc cấp token.';
COMMENT ON COLUMN persistent_login_token.user_agent IS 'User-Agent trình duyệt lúc cấp token.';
COMMENT ON COLUMN persistent_login_token.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN persistent_login_token.last_used_at IS 'Lần xoay token gần nhất.';
COMMENT ON COLUMN persistent_login_token.expires_at IS 'Hết hạn (phải sau created_at).';

-- -----------------------------------------------------------------------------
-- 1.3. Bảng: password_reset_token
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

COMMENT ON TABLE password_reset_token IS 'Kho token dùng một lần cho "Quên mật khẩu" và "Đặt lại mật khẩu". Chỉ lưu băm; token hết hạn hoặc đã dùng (used_at) không còn hiệu lực. Bảng này cho phép DELETE trực tiếp để dọn token.';
COMMENT ON COLUMN password_reset_token.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN password_reset_token.account_id IS 'Tài khoản yêu cầu đặt lại mật khẩu (FK → account).';
COMMENT ON COLUMN password_reset_token.token_hash IS 'Giá trị băm của token dùng một lần; duy nhất. Token thô không lưu.';
COMMENT ON COLUMN password_reset_token.expires_at IS 'Thời điểm hết hạn (phải sau created_at).';
COMMENT ON COLUMN password_reset_token.used_at IS 'Thời điểm đã dùng; NULL nếu chưa dùng.';
COMMENT ON COLUMN password_reset_token.requested_ip IS 'Địa chỉ IP nơi yêu cầu (phục vụ kiểm tra an ninh).';
COMMENT ON COLUMN password_reset_token.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';

-- =============================================================================
-- PHẦN 2: NHÂN SỰ VÀ ĐỊA GIỚI HÀNH CHÍNH
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 2.1. Bảng: position
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

COMMENT ON TABLE position IS 'Danh mục chức vụ (Quản lý, Nhân viên vận hành, Nhân viên thu ngân, Kỹ thuật viên).';
COMMENT ON COLUMN position.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN position.code IS 'Mã chức vụ (QL, NVVH, NVTN, KTV); duy nhất.';
COMMENT ON COLUMN position.name IS 'Tên chức vụ; duy nhất.';
COMMENT ON COLUMN position.description IS 'Mô tả (tuỳ chọn).';
COMMENT ON COLUMN position.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN position.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN position.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN position.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN position.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 2.2. Các bảng: administrative_province, administrative_district, administrative_ward
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

COMMENT ON TABLE administrative_province IS 'Danh mục tỉnh/thành phố, dùng cho địa chỉ của nhân viên và khách hàng. Bất biến, không xoá cứng.';
COMMENT ON COLUMN administrative_province.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN administrative_province.code IS 'Mã tỉnh/thành, duy nhất.';
COMMENT ON COLUMN administrative_province.name IS 'Tên tỉnh/thành phố.';
COMMENT ON COLUMN administrative_province.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN administrative_province.updated_at IS 'Thời điểm sửa gần nhất.';

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

COMMENT ON TABLE administrative_district IS 'Danh mục quận/huyện thuộc tỉnh. Khoá duy nhất (id, province_id) để các bảng khác ràng buộc đúng phân cấp.';
COMMENT ON COLUMN administrative_district.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN administrative_district.province_id IS 'Tỉnh/thành chứa quận/huyện (FK → administrative_province).';
COMMENT ON COLUMN administrative_district.code IS 'Mã quận/huyện, duy nhất.';
COMMENT ON COLUMN administrative_district.name IS 'Tên quận/huyện.';
COMMENT ON COLUMN administrative_district.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN administrative_district.updated_at IS 'Thời điểm sửa gần nhất.';

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

COMMENT ON TABLE administrative_ward IS 'Danh mục phường/xã thuộc quận/huyện, với khoá duy nhất (id, district_id) tương tự.';
COMMENT ON COLUMN administrative_ward.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN administrative_ward.district_id IS 'Quận/huyện chứa phường/xã (FK → administrative_district).';
COMMENT ON COLUMN administrative_ward.code IS 'Mã phường/xã, duy nhất.';
COMMENT ON COLUMN administrative_ward.name IS 'Tên phường/xã.';
COMMENT ON COLUMN administrative_ward.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN administrative_ward.updated_at IS 'Thời điểm sửa gần nhất.';

-- -----------------------------------------------------------------------------
-- 2.3. Bảng: employee
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

COMMENT ON TABLE employee IS 'Hồ sơ nhân viên: mã NV, họ tên, liên hệ, chức vụ, địa chỉ ba cấp và trạng thái làm việc. Có thể liên kết một tài khoản đăng nhập.';
COMMENT ON COLUMN employee.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN employee.code IS 'Mã nhân viên dạng NV + 3-4 chữ số (NV005, NV0005).';
COMMENT ON COLUMN employee.full_name IS 'Họ và tên (bắt buộc, tối đa 45 ký tự).';
COMMENT ON COLUMN employee.date_of_birth IS 'Ngày sinh (tuỳ chọn, phải ở quá khứ).';
COMMENT ON COLUMN employee.gender IS 'Giới tính, chỉ nhận "Nam" hoặc "Nữ" khi có giá trị.';
COMMENT ON COLUMN employee.identity_card_number IS 'Số CCCD/CMND (tuỳ chọn, 9-20 chữ số); duy nhất trong nhân viên chưa xoá.';
COMMENT ON COLUMN employee.phone IS 'Số điện thoại (9-15 chữ số, bắt buộc); duy nhất trong nhân viên chưa xoá.';
COMMENT ON COLUMN employee.email IS 'Email công việc (bắt buộc); duy nhất không phân biệt hoa thường.';
COMMENT ON COLUMN employee.address IS 'Địa chỉ chi tiết (tuỳ chọn).';
COMMENT ON COLUMN employee.province_id IS 'Tỉnh/thành (FK → administrative_province).';
COMMENT ON COLUMN employee.district_id IS 'Quận/huyện; cặp (district_id, province_id) phải khớp phân cấp.';
COMMENT ON COLUMN employee.ward_id IS 'Phường/xã; cặp (ward_id, district_id) phải khớp phân cấp.';
COMMENT ON COLUMN employee.position_id IS 'Chức vụ (FK → position, bắt buộc).';
COMMENT ON COLUMN employee.account_id IS 'Tài khoản đăng nhập của nhân viên (tuỳ chọn); mỗi tài khoản gắn tối đa một nhân viên.';
COMMENT ON COLUMN employee.status IS 'Trạng thái làm việc: ACTIVE hoặc INACTIVE.';
COMMENT ON COLUMN employee.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN employee.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN employee.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN employee.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN employee.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- =============================================================================
-- PHẦN 3: KHÁCH HÀNG, DANH SÁCH ĐEN VÀ XE
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 3.1. Bảng: customer
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

-- Chỉ mục GIN trigram giúp tìm kiếm chuỗi con/ILIKE nhanh
CREATE INDEX idx_customer_full_name_trgm ON customer USING gin (full_name gin_trgm_ops) WHERE deleted_at IS NULL;
CREATE INDEX idx_customer_phone_trgm ON customer USING gin (phone gin_trgm_ops) WHERE deleted_at IS NULL;
CREATE INDEX idx_customer_idcard_trgm ON customer USING gin (identity_card_number gin_trgm_ops) WHERE deleted_at IS NULL;

COMMENT ON TABLE customer IS 'Hồ sơ khách hàng kèm trạng thái vận hành ACTIVE, SUSPENDED, BLACKLISTED và lý do. Có cờ ẩn danh dữ liệu cá nhân trước khi được phép xoá vĩnh viễn.';
COMMENT ON COLUMN customer.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN customer.code IS 'Mã khách hàng ("Mã KH", ví dụ KH0011); duy nhất trong bản ghi chưa xoá.';
COMMENT ON COLUMN customer.full_name IS 'Họ và tên (bắt buộc, tối đa 45 ký tự).';
COMMENT ON COLUMN customer.date_of_birth IS 'Ngày sinh (tuỳ chọn, phải ở quá khứ).';
COMMENT ON COLUMN customer.gender IS 'Giới tính, chỉ nhận "Nam" hoặc "Nữ" khi có giá trị.';
COMMENT ON COLUMN customer.identity_card_number IS 'Số CCCD/CMND (9-20 chữ số, bắt buộc); duy nhất trong khách chưa xoá và chưa ẩn danh.';
COMMENT ON COLUMN customer.phone IS 'Số điện thoại (9-15 chữ số, bắt buộc); duy nhất trong khách chưa xoá và chưa ẩn danh.';
COMMENT ON COLUMN customer.email IS 'Email (tuỳ chọn); duy nhất không phân biệt hoa thường trong khách chưa xoá và chưa ẩn danh.';
COMMENT ON COLUMN customer.address IS 'Địa chỉ chi tiết (tuỳ chọn).';
COMMENT ON COLUMN customer.province_id IS 'Tỉnh/thành (FK → administrative_province).';
COMMENT ON COLUMN customer.district_id IS 'Quận/huyện; cặp (district_id, province_id) phải khớp phân cấp hành chính.';
COMMENT ON COLUMN customer.ward_id IS 'Phường/xã; cặp (ward_id, district_id) phải khớp phân cấp hành chính.';
COMMENT ON COLUMN customer.account_id IS 'Tài khoản đăng nhập nếu khách tự đăng ký (tuỳ chọn); mỗi tài khoản gắn tối đa một khách.';
COMMENT ON COLUMN customer.status IS 'Trạng thái vận hành: ACTIVE, SUSPENDED (tạm ngừng) hoặc BLACKLISTED.';
COMMENT ON COLUMN customer.status_reason IS 'Lý do tạm ngừng/đưa vào danh sách đen; bắt buộc khi BLACKLISTED.';
COMMENT ON COLUMN customer.is_anonymized IS 'Cờ đã ẩn danh dữ liệu cá nhân.';
COMMENT ON COLUMN customer.anonymized_at IS 'Thời điểm ẩn danh; phải có giá trị khi và chỉ khi is_anonymized = TRUE.';
COMMENT ON COLUMN customer.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN customer.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN customer.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN customer.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN customer.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 3.2. Bảng: plate_blacklist
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

COMMENT ON TABLE plate_blacklist IS 'Danh sách đen biển số cho xe vãng lai hoặc chưa đăng ký, kèm lý do và số tiền nợ. Mỗi biển chuẩn hoá chỉ có một mục đang hiệu lực.';
COMMENT ON COLUMN plate_blacklist.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN plate_blacklist.license_plate IS 'Biển số dạng người nhập (51G-888.88).';
COMMENT ON COLUMN plate_blacklist.license_plate_norm IS 'Biển số chuẩn hoá do fn_normalize_license_plate tự sinh (cột generated, lưu trữ).';
COMMENT ON COLUMN plate_blacklist.reason IS 'Lý do đưa vào danh sách đen (bắt buộc).';
COMMENT ON COLUMN plate_blacklist.unpaid_amount IS 'Số tiền còn nợ, VND (≥ 0).';
COMMENT ON COLUMN plate_blacklist.is_active IS 'Mục đang có hiệu lực.';
COMMENT ON COLUMN plate_blacklist.added_by IS 'Nhân viên ghi nhận (FK → employee).';
COMMENT ON COLUMN plate_blacklist.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN plate_blacklist.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN plate_blacklist.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN plate_blacklist.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN plate_blacklist.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 3.3. Bảng: vehicle_type
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

COMMENT ON TABLE vehicle_type IS 'Danh mục loại xe. Hiện có hai loại: CAR (Ô tô) và EV (Xe điện).';
COMMENT ON COLUMN vehicle_type.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN vehicle_type.code IS 'Mã loại xe (CAR, EV); duy nhất.';
COMMENT ON COLUMN vehicle_type.name IS 'Tên loại xe (Ô tô, Xe điện); duy nhất.';
COMMENT ON COLUMN vehicle_type.description IS 'Mô tả (tuỳ chọn).';
COMMENT ON COLUMN vehicle_type.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN vehicle_type.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN vehicle_type.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN vehicle_type.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN vehicle_type.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 3.4. Bảng: ticket_type
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

COMMENT ON TABLE ticket_type IS 'Bảng giá loại vé: ngày, tháng, quý, năm với thời hạn và giá niêm yết.';
COMMENT ON COLUMN ticket_type.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN ticket_type.code IS 'Mã loại vé (DAILY, MONTHLY, QUARTERLY, YEARLY).';
COMMENT ON COLUMN ticket_type.name IS 'Tên loại vé (Vé ngày, Vé tháng...).';
COMMENT ON COLUMN ticket_type.duration_days IS 'Thời hạn, ngày (1, 30, 90, 365; > 0).';
COMMENT ON COLUMN ticket_type.default_price IS 'Giá niêm yết, VND (≥ 0).';
COMMENT ON COLUMN ticket_type.description IS 'Mô tả (tuỳ chọn).';
COMMENT ON COLUMN ticket_type.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN ticket_type.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN ticket_type.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN ticket_type.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN ticket_type.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 3.5. Bảng: vehicle
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

COMMENT ON TABLE vehicle IS 'Lưu xe của khách hàng. Biển số lưu hai dạng: dạng người nhập để hiển thị và dạng chuẩn hoá (cột generated) để so khớp, kiểm tra trùng và tìm kiếm. Đồng bộ thông tin vé đang hiệu lực từ bảng ticket.';
COMMENT ON COLUMN vehicle.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN vehicle.code IS 'Mã xe (XE0007...); duy nhất trong xe chưa xoá.';
COMMENT ON COLUMN vehicle.license_plate IS 'Biển số như người nhập, dùng để hiển thị (43T-814.62).';
COMMENT ON COLUMN vehicle.license_plate_norm IS 'Biển số chuẩn hoá (43T81462), cột generated lưu trữ; duy nhất trong xe chưa xoá.';
COMMENT ON COLUMN vehicle.model_name IS 'Dòng xe (City RS...).';
COMMENT ON COLUMN vehicle.brand IS 'Hãng xe (tuỳ chọn).';
COMMENT ON COLUMN vehicle.color IS 'Màu xe (tuỳ chọn).';
COMMENT ON COLUMN vehicle.image_url IS 'Đường dẫn ảnh xe (tuỳ chọn).';
COMMENT ON COLUMN vehicle.notes IS 'Ghi chú.';
COMMENT ON COLUMN vehicle.vehicle_type_id IS 'Loại xe (CAR, EV).';
COMMENT ON COLUMN vehicle.customer_id IS 'Chủ xe (FK → customer).';
COMMENT ON COLUMN vehicle.ticket_type_id IS 'Loại vé đang hiệu lực, đồng bộ tự động từ bảng ticket.';
COMMENT ON COLUMN vehicle.ticket_expires_at IS 'Hạn vé đang hiệu lực, đồng bộ tự động; cùng NULL hoặc cùng có giá trị với ticket_type_id.';
COMMENT ON COLUMN vehicle.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN vehicle.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN vehicle.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN vehicle.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN vehicle.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- =============================================================================
-- PHẦN 4: CẤU TRÚC BÃI ĐỖ, Ô ĐỖ VÀ ĐẶT CHỖ
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 4.1. Bảng: parking_lot
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

COMMENT ON TABLE parking_lot IS 'Lưu bãi đỗ xe, cấp cao nhất của cấu trúc bãi. Dữ liệu mẫu có một bãi "Bãi xe Smart Mobility".';
COMMENT ON COLUMN parking_lot.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN parking_lot.code IS 'Mã bãi (SMART_MOBILITY), duy nhất.';
COMMENT ON COLUMN parking_lot.name IS 'Tên bãi, duy nhất trong bãi chưa xoá.';
COMMENT ON COLUMN parking_lot.address IS 'Địa chỉ bãi.';
COMMENT ON COLUMN parking_lot.is_active IS 'Bãi đang hoạt động.';
COMMENT ON COLUMN parking_lot.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN parking_lot.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN parking_lot.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN parking_lot.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN parking_lot.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 4.1.1. Bảng: booking_policy
-- Bảng cấu hình chính sách đặt chỗ, mỗi bãi đỗ xe một chính sách đang hiệu lực.
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

COMMENT ON TABLE booking_policy IS 'Lưu tham số chính sách đặt trước của một bãi (thời gian giữ chỗ, ân hạn, vào sớm, số ngày đặt trước tối đa, độ dài tối thiểu/tối đa, tiền cọc, hạn huỷ miễn phí). Mỗi bãi có tối đa một chính sách hoạt động.';
COMMENT ON COLUMN booking_policy.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN booking_policy.lot_id IS 'Bãi đỗ áp dụng chính sách; tối đa một chính sách chưa xoá mềm cho mỗi bãi.';
COMMENT ON COLUMN booking_policy.hold_minutes IS 'Số phút giữ chỗ chờ thanh toán cọc (mặc định 15).';
COMMENT ON COLUMN booking_policy.grace_minutes IS 'Số phút ân hạn sau giờ bắt đầu trước khi tính NO_SHOW (mặc định 15).';
COMMENT ON COLUMN booking_policy.early_checkin_minutes IS 'Số phút được phép vào sớm trước giờ bắt đầu (mặc định 15).';
COMMENT ON COLUMN booking_policy.max_advance_days IS 'Số ngày tối đa được đặt trước (mặc định 7).';
COMMENT ON COLUMN booking_policy.min_duration_minutes IS 'Thời lượng đặt tối thiểu, phút (mặc định 30, tối thiểu cho phép 15).';
COMMENT ON COLUMN booking_policy.max_duration_minutes IS 'Thời lượng đặt tối đa, phút (mặc định 1440 = 24 giờ).';
COMMENT ON COLUMN booking_policy.deposit_amount IS 'Tiền cọc, VND (mặc định 50.000; 0 nghĩa là không cần cọc).';
COMMENT ON COLUMN booking_policy.cancel_free_before_minutes IS 'Huỷ trước giờ bắt đầu ít nhất bấy nhiêu phút thì hoàn đủ cọc (mặc định 60).';
COMMENT ON COLUMN booking_policy.is_active IS 'Chính sách có đang áp dụng hay không.';
COMMENT ON COLUMN booking_policy.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN booking_policy.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN booking_policy.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN booking_policy.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN booking_policy.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 4.2. Bảng: parking_floor
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

COMMENT ON TABLE parking_floor IS 'Lưu tầng của bãi (B1, B2, F1) kèm thứ tự hiển thị.';
COMMENT ON COLUMN parking_floor.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN parking_floor.lot_id IS 'Bãi đỗ chứa tầng (FK → parking_lot).';
COMMENT ON COLUMN parking_floor.code IS 'Mã tầng (B1, B2, F1...); duy nhất trong bãi.';
COMMENT ON COLUMN parking_floor.name IS 'Tên hiển thị (Tầng B1...); duy nhất trong bãi.';
COMMENT ON COLUMN parking_floor.sort_order IS 'Thứ tự hiển thị (> 0).';
COMMENT ON COLUMN parking_floor.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN parking_floor.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN parking_floor.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN parking_floor.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN parking_floor.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 4.3. Bảng: parking_zone
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

COMMENT ON TABLE parking_zone IS 'Lưu khu trong một tầng (Khu A, Khu B, Khu VIP...).';
COMMENT ON COLUMN parking_zone.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN parking_zone.floor_id IS 'Tầng chứa khu (FK → parking_floor).';
COMMENT ON COLUMN parking_zone.code IS 'Mã khu; duy nhất trong tầng.';
COMMENT ON COLUMN parking_zone.name IS 'Tên khu (Khu A, Khu VIP...); duy nhất trong tầng.';
COMMENT ON COLUMN parking_zone.description IS 'Mô tả khu (tuỳ chọn).';
COMMENT ON COLUMN parking_zone.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN parking_zone.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN parking_zone.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN parking_zone.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN parking_zone.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 4.4. Bảng: parking_slot
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

COMMENT ON TABLE parking_slot IS 'Lưu ô đỗ vật lý với 5 trạng thái vận hành, 3 loại ô, toạ độ trên sơ đồ và kích thước.';
COMMENT ON COLUMN parking_slot.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN parking_slot.zone_id IS 'Khu chứa ô đỗ (FK → parking_zone).';
COMMENT ON COLUMN parking_slot.code IS 'Mã ô trong khu (A-01, A10...); duy nhất trong khu.';
COMMENT ON COLUMN parking_slot.slot_kind IS 'Loại ô: STANDARD, PRIORITY hoặc EV_CHARGING.';
COMMENT ON COLUMN parking_slot.status IS 'Trạng thái: AVAILABLE, OCCUPIED, RESERVED, CHARGING hoặc MAINTENANCE.';
COMMENT ON COLUMN parking_slot.map_row IS 'Hàng trên lưới sơ đồ (bắt đầu từ 1).';
COMMENT ON COLUMN parking_slot.map_col IS 'Cột trên lưới sơ đồ (bắt đầu từ 1); cặp (row, col) duy nhất trong khu.';
COMMENT ON COLUMN parking_slot.width IS 'Chiều rộng ô, mét (> 0, mặc định 2,50).';
COMMENT ON COLUMN parking_slot.length IS 'Chiều dài ô, mét (> 0, mặc định 5,00).';
COMMENT ON COLUMN parking_slot.height IS 'Chiều cao thông thuỷ, mét (> 0, mặc định 2,20).';
COMMENT ON COLUMN parking_slot.notes IS 'Ghi chú tự do (tuỳ chọn).';
COMMENT ON COLUMN parking_slot.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN parking_slot.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN parking_slot.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN parking_slot.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN parking_slot.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 4.5. Bảng: slot_allowed_vehicle_type
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

COMMENT ON TABLE slot_allowed_vehicle_type IS 'Bảng nối nhiều-nhiều cho biết mỗi ô cho phép loại xe nào. Là điều kiện kiểm tra khi cấp vé, đặt chỗ và cho xe vào.';
COMMENT ON COLUMN slot_allowed_vehicle_type.slot_id IS 'Ô đỗ (FK → parking_slot).';
COMMENT ON COLUMN slot_allowed_vehicle_type.vehicle_type_id IS 'Loại xe được phép đỗ (FK → vehicle_type).';
COMMENT ON COLUMN slot_allowed_vehicle_type.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';

-- -----------------------------------------------------------------------------
-- 4.6. Bảng: slot_reservation
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

COMMENT ON TABLE slot_reservation IS 'Lưu lượt đặt trước một ô đỗ trong khung giờ, với vòng đời 7 trạng thái và hai ràng buộc EXCLUDE chống đặt trùng ô và trùng xe. Là bảng trung tâm của mô-đun đặt chỗ.';
COMMENT ON COLUMN slot_reservation.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN slot_reservation.code IS 'Mã đặt chỗ dạng RSV-YYYYMMDD-XXXXXX; duy nhất trong bản ghi chưa xoá.';
COMMENT ON COLUMN slot_reservation.slot_id IS 'Ô đỗ được đặt (FK → parking_slot).';
COMMENT ON COLUMN slot_reservation.customer_id IS 'Khách hàng đặt (NULL với khách vãng lai do nhân viên đặt hộ).';
COMMENT ON COLUMN slot_reservation.vehicle_id IS 'Xe đặt (NULL với khách vãng lai).';
COMMENT ON COLUMN slot_reservation.booking_channel IS 'Kênh đặt: CUSTOMER_PORTAL hoặc STAFF.';
COMMENT ON COLUMN slot_reservation.reserved_name IS 'Tên người đặt khi đặt cho khách vãng lai.';
COMMENT ON COLUMN slot_reservation.reserved_phone IS 'Số điện thoại người đặt (9-15 chữ số).';
COMMENT ON COLUMN slot_reservation.reserved_from IS 'Bắt đầu giữ chỗ (bao gồm).';
COMMENT ON COLUMN slot_reservation.reserved_until IS 'Kết thúc giữ chỗ (không bao gồm), phải sau reserved_from.';
COMMENT ON COLUMN slot_reservation.status IS 'Trạng thái: PENDING_PAYMENT, CONFIRMED, CHECKED_IN, COMPLETED, CANCELLED, EXPIRED, NO_SHOW.';
COMMENT ON COLUMN slot_reservation.hold_expires_at IS 'Hạn thanh toán cọc; bắt buộc khi PENDING_PAYMENT.';
COMMENT ON COLUMN slot_reservation.deposit_amount IS 'Tiền cọc, VND (chụp từ chính sách lúc đặt).';
COMMENT ON COLUMN slot_reservation.checked_in_at IS 'Thời điểm xe vào cổng; bắt buộc khi CHECKED_IN.';
COMMENT ON COLUMN slot_reservation.completed_at IS 'Thời điểm xe ra, hoàn tất; bắt buộc khi COMPLETED.';
COMMENT ON COLUMN slot_reservation.cancelled_at IS 'Thời điểm huỷ; bắt buộc khi CANCELLED.';
COMMENT ON COLUMN slot_reservation.cancelled_by IS 'Tài khoản huỷ (FK → account).';
COMMENT ON COLUMN slot_reservation.cancel_reason IS 'Lý do huỷ.';
COMMENT ON COLUMN slot_reservation.no_show_at IS 'Thời điểm đánh dấu NO_SHOW; bắt buộc khi NO_SHOW.';
COMMENT ON COLUMN slot_reservation.notes IS 'Ghi chú.';
COMMENT ON COLUMN slot_reservation.created_by IS 'Nhân viên tạo (FK → employee), dùng cho kênh STAFF.';
COMMENT ON COLUMN slot_reservation.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN slot_reservation.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN slot_reservation.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN slot_reservation.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN slot_reservation.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- =============================================================================
-- PHẦN 5: VÉ VÀ GIA HẠN
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 5.1. Bảng: ticket
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

COMMENT ON TABLE ticket IS 'Lưu vé đã phát hành gắn một xe, một khách và một ô cố định trong khoảng hiệu lực. EXCLUDE chống hai vé chồng hiệu lực trên một ô; trạng thái hết hạn được tự cập nhật.';
COMMENT ON COLUMN ticket.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN ticket.code IS 'Mã vé (VT0001...); duy nhất trong vé chưa xoá.';
COMMENT ON COLUMN ticket.vehicle_id IS 'Xe được cấp vé; cùng customer_id tạo khoá ngoại ghép bảo đảm xe thuộc đúng chủ vé.';
COMMENT ON COLUMN ticket.customer_id IS 'Chủ vé (FK → customer).';
COMMENT ON COLUMN ticket.slot_id IS 'Ô đỗ cố định gắn với vé.';
COMMENT ON COLUMN ticket.ticket_type_id IS 'Loại vé (FK → ticket_type).';
COMMENT ON COLUMN ticket.issued_by IS 'Nhân viên phát hành (FK → employee).';
COMMENT ON COLUMN ticket.price IS 'Giá vé thực thu, VND (≥ 0).';
COMMENT ON COLUMN ticket.effective_from IS 'Bắt đầu hiệu lực.';
COMMENT ON COLUMN ticket.effective_to IS 'Hết hiệu lực, phải sau effective_from.';
COMMENT ON COLUMN ticket.status IS 'Trạng thái lưu: ACTIVE, EXPIRED, CANCELLED, RENEWING ("sắp hết hạn" suy ra từ effective_to).';
COMMENT ON COLUMN ticket.notes IS 'Ghi chú.';
COMMENT ON COLUMN ticket.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN ticket.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN ticket.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN ticket.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN ticket.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 5.2. Bảng: ticket_renewal
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

COMMENT ON TABLE ticket_renewal IS 'Nhật ký các lần gia hạn vé: ô, loại vé, giá và hạn trước/sau, phí thu thêm.';
COMMENT ON COLUMN ticket_renewal.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN ticket_renewal.ticket_id IS 'Vé được gia hạn.';
COMMENT ON COLUMN ticket_renewal.old_slot_id IS 'Ô đỗ trước gia hạn.';
COMMENT ON COLUMN ticket_renewal.new_slot_id IS 'Ô đỗ sau gia hạn (có thể đổi ô).';
COMMENT ON COLUMN ticket_renewal.old_ticket_type_id IS 'Loại vé trước gia hạn.';
COMMENT ON COLUMN ticket_renewal.new_ticket_type_id IS 'Loại vé sau gia hạn.';
COMMENT ON COLUMN ticket_renewal.old_price IS 'Giá vé trước gia hạn.';
COMMENT ON COLUMN ticket_renewal.new_price IS 'Giá vé mới.';
COMMENT ON COLUMN ticket_renewal.old_effective_to IS 'Hạn cũ.';
COMMENT ON COLUMN ticket_renewal.new_effective_to IS 'Hạn mới, phải sau hạn cũ.';
COMMENT ON COLUMN ticket_renewal.additional_price IS 'Phí gia hạn thu thêm, VND (≥ 0).';
COMMENT ON COLUMN ticket_renewal.notes IS 'Ghi chú gia hạn.';
COMMENT ON COLUMN ticket_renewal.renewed_by IS 'Nhân viên xử lý gia hạn (FK → employee).';
COMMENT ON COLUMN ticket_renewal.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN ticket_renewal.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';

-- =============================================================================
-- PHẦN 6: CỔNG, PHIÊN RA/VÀO VÀ THANH TOÁN
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 6.1. Bảng: parking_gate
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

COMMENT ON TABLE parking_gate IS 'Lưu cổng vào/ra kèm hướng, tình trạng camera biển số và cờ quét tự động.';
COMMENT ON COLUMN parking_gate.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN parking_gate.lot_id IS 'Bãi đỗ chứa cổng (FK → parking_lot).';
COMMENT ON COLUMN parking_gate.code IS 'Mã cổng (IN_01, OUT_01); duy nhất trong bãi.';
COMMENT ON COLUMN parking_gate.name IS 'Tên hiển thị (Cổng vào 1...); duy nhất trong bãi.';
COMMENT ON COLUMN parking_gate.direction IS 'Hướng: IN (vào) hoặc OUT (ra).';
COMMENT ON COLUMN parking_gate.camera_status IS 'Tình trạng camera biển số: ONLINE, LOW_LIGHT, DEGRADED hoặc OFFLINE.';
COMMENT ON COLUMN parking_gate.is_auto_scan IS 'Bật nhận diện biển số tự động tại cổng.';
COMMENT ON COLUMN parking_gate.is_active IS 'Cổng đang hoạt động.';
COMMENT ON COLUMN parking_gate.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN parking_gate.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN parking_gate.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN parking_gate.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN parking_gate.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 6.2. Bảng: vehicle_entry_exit_log
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

COMMENT ON TABLE vehicle_entry_exit_log IS 'Lưu phiên đỗ xe qua cổng, gồm cả xe đã đăng ký và khách vãng lai (vehicle_id NULL). Lưu biển số, độ tin cậy nhận diện, nguồn nhận diện, ảnh đối soát và cước phí.';
COMMENT ON COLUMN vehicle_entry_exit_log.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN vehicle_entry_exit_log.session_code IS 'Mã phiên đỗ (#PK-20261017-001); duy nhất.';
COMMENT ON COLUMN vehicle_entry_exit_log.vehicle_id IS 'Xe đã đăng ký; NULL với khách vãng lai.';
COMMENT ON COLUMN vehicle_entry_exit_log.slot_id IS 'Ô đỗ đang chiếm (tuỳ chọn).';
COMMENT ON COLUMN vehicle_entry_exit_log.ticket_id IS 'Vé áp dụng cho phiên (tuỳ chọn).';
COMMENT ON COLUMN vehicle_entry_exit_log.reservation_id IS 'Lượt đặt trước mà phiên này hoàn thành; mỗi lượt đặt chỉ gắn tối đa một phiên.';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_gate_id IS 'Cổng vào.';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_gate_id IS 'Cổng ra.';
COMMENT ON COLUMN vehicle_entry_exit_log.license_plate IS 'Biển số chụp/nhập tại cổng.';
COMMENT ON COLUMN vehicle_entry_exit_log.license_plate_norm IS 'Biển số chuẩn hoá, cột generated lưu trữ; chỉ một phiên mở cho mỗi biển.';
COMMENT ON COLUMN vehicle_entry_exit_log.ai_confidence IS 'Độ tin cậy nhận diện biển số 0-100 (%).';
COMMENT ON COLUMN vehicle_entry_exit_log.recognition_source IS 'Nguồn: AI hoặc MANUAL.';
COMMENT ON COLUMN vehicle_entry_exit_log.review_status IS 'Duyệt: AUTO, MATCHED, NEEDS_REVIEW, APPROVED, REJECTED.';
COMMENT ON COLUMN vehicle_entry_exit_log.fee_amount IS 'Cước phí phiên, VND (≥ 0).';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_time IS 'Thời gian vào.';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_time IS 'Thời gian ra; NULL khi xe còn trong bãi (không được trước entry_time).';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_image_url IS 'Ảnh đối soát lúc vào.';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_image_url IS 'Ảnh đối soát lúc ra.';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_handled_by IS 'Nhân viên trực lúc vào.';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_handled_by IS 'Nhân viên trực lúc ra.';
COMMENT ON COLUMN vehicle_entry_exit_log.notes IS 'Ghi chú của người vận hành.';
COMMENT ON COLUMN vehicle_entry_exit_log.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN vehicle_entry_exit_log.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';

-- -----------------------------------------------------------------------------
-- 6.3. Bảng: payment
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

COMMENT ON TABLE payment IS 'Sổ chứng từ thanh toán thống nhất cho tiền mặt và VietQR. Mỗi chứng từ nhắm đúng một mục tiêu: phiên đỗ, vé, gia hạn hoặc tiền cọc đặt chỗ.';
COMMENT ON COLUMN payment.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN payment.code IS 'Mã chứng từ thanh toán; duy nhất trong bản ghi chưa xoá.';
COMMENT ON COLUMN payment.amount IS 'Số tiền, VND (≥ 0).';
COMMENT ON COLUMN payment.method IS 'Phương thức: CASH hoặc VIETQR.';
COMMENT ON COLUMN payment.status IS 'Trạng thái: UNPAID, PAID, CANCELLED hoặc REFUNDED.';
COMMENT ON COLUMN payment.paid_at IS 'Thời điểm thanh toán; bắt buộc khi PAID hoặc REFUNDED.';
COMMENT ON COLUMN payment.received_by IS 'Nhân viên thu tiền (FK → employee, tuỳ chọn).';
COMMENT ON COLUMN payment.provider_ref IS 'Mã tham chiếu bên ngoài / nội dung chuyển khoản VietQR (tuỳ chọn).';
COMMENT ON COLUMN payment.session_id IS 'Mục tiêu thanh toán: phiên ra/vào (đúng một trong bốn cột mục tiêu phải khác NULL).';
COMMENT ON COLUMN payment.ticket_id IS 'Mục tiêu thanh toán: vé mua mới.';
COMMENT ON COLUMN payment.renewal_id IS 'Mục tiêu thanh toán: lần gia hạn vé.';
COMMENT ON COLUMN payment.reservation_id IS 'Mục tiêu thanh toán: tiền cọc đặt trước chỗ.';
COMMENT ON COLUMN payment.notes IS 'Ghi chú (hệ thống nối thêm lý do hoàn/tịch thu cọc).';
COMMENT ON COLUMN payment.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN payment.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN payment.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN payment.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN payment.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- =============================================================================
-- PHẦN 7: NHẬT KÝ HOẠT ĐỘNG, CẢNH BÁO, TIN TỨC VÀ THÔNG BÁO
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 7.1. Bảng: activity_log
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

COMMENT ON TABLE activity_log IS 'Nhật ký hoạt động chỉ ghi thêm cho mục "Hoạt động gần đây", đồng thời là nơi ghi vết SOFT_DELETE, RESTORE, PURGE.';
COMMENT ON COLUMN activity_log.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN activity_log.actor_account_id IS 'Tài khoản thực hiện (NULL với sự kiện tự động của cổng/hệ thống).';
COMMENT ON COLUMN activity_log.action IS 'Mã hành động (SOFT_DELETE, RESTORE, PURGE, SLOT_CHECKIN...).';
COMMENT ON COLUMN activity_log.entity_type IS 'Loại thực thể bị tác động (tên bảng hoặc loại nghiệp vụ).';
COMMENT ON COLUMN activity_log.entity_id IS 'Khoá của bản ghi bị tác động (có thể NULL).';
COMMENT ON COLUMN activity_log.message IS 'Mô tả tiếng Việt hiển thị ở mục "Hoạt động gần đây".';
COMMENT ON COLUMN activity_log.occurred_at IS 'Thời điểm xảy ra hoạt động.';

-- -----------------------------------------------------------------------------
-- 7.2. Bảng: system_alert
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

COMMENT ON TABLE system_alert IS 'Lưu cảnh báo bất thường và khẩn cấp (biển đen, quá hạn, chất lượng camera, hệ thống).';
COMMENT ON COLUMN system_alert.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN system_alert.alert_type IS 'Loại: BLACKLIST_PLATE, OVERSTAY, CAMERA_QUALITY hoặc SYSTEM.';
COMMENT ON COLUMN system_alert.severity IS 'Mức độ: INFO, WARNING hoặc CRITICAL.';
COMMENT ON COLUMN system_alert.message IS 'Nội dung cảnh báo.';
COMMENT ON COLUMN system_alert.entity_type IS 'Loại thực thể liên quan (tuỳ chọn).';
COMMENT ON COLUMN system_alert.entity_id IS 'Khoá thực thể liên quan (tuỳ chọn).';
COMMENT ON COLUMN system_alert.occurred_at IS 'Thời điểm phát sinh.';
COMMENT ON COLUMN system_alert.resolved_at IS 'Thời điểm xử lý; NULL nghĩa là còn "cần xử lý".';
COMMENT ON COLUMN system_alert.resolved_by IS 'Nhân viên xử lý (FK → employee).';
COMMENT ON COLUMN system_alert.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';

-- -----------------------------------------------------------------------------
-- 7.3. Bảng: news
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

COMMENT ON TABLE news IS 'Lưu bài viết tin tức và thông báo của bãi, có slug, trạng thái xuất bản và lượt xem.';
COMMENT ON COLUMN news.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN news.title IS 'Tiêu đề bài viết.';
COMMENT ON COLUMN news.slug IS 'Đường dẫn thân thiện (chữ thường, số, gạch ngang); duy nhất trong bài chưa xoá.';
COMMENT ON COLUMN news.summary IS 'Tóm tắt ngắn (tuỳ chọn, tối đa 500 ký tự).';
COMMENT ON COLUMN news.content IS 'Nội dung đầy đủ, không rỗng.';
COMMENT ON COLUMN news.thumbnail_url IS 'Đường dẫn ảnh đại diện (tuỳ chọn).';
COMMENT ON COLUMN news.author_id IS 'Nhân viên tác giả (FK → employee).';
COMMENT ON COLUMN news.is_published IS 'Cờ đã xuất bản (mặc định FALSE).';
COMMENT ON COLUMN news.published_at IS 'Thời điểm xuất bản.';
COMMENT ON COLUMN news.view_count IS 'Số lượt xem, không âm.';
COMMENT ON COLUMN news.row_version IS 'Số phiên bản dùng cho khoá lạc quan (luôn ≥ 1, mặc định 1).';
COMMENT ON COLUMN news.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN news.updated_at IS 'Thời điểm sửa gần nhất.';
COMMENT ON COLUMN news.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN news.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- -----------------------------------------------------------------------------
-- 7.4. Bảng: notification
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

COMMENT ON TABLE notification IS 'Lưu thông báo gửi tới một tài khoản hoặc toàn hệ thống (recipient_account_id NULL).';
COMMENT ON COLUMN notification.id IS 'Khoá chính, tự tăng (sequence).';
COMMENT ON COLUMN notification.recipient_account_id IS 'Tài khoản nhận; NULL nghĩa là thông báo toàn hệ thống.';
COMMENT ON COLUMN notification.title IS 'Tiêu đề thông báo.';
COMMENT ON COLUMN notification.content IS 'Nội dung thông báo.';
COMMENT ON COLUMN notification.notification_type IS 'Loại: SYSTEM, TICKET_EXPIRY, PAYMENT hoặc SECURITY.';
COMMENT ON COLUMN notification.is_read IS 'Đã đọc hay chưa.';
COMMENT ON COLUMN notification.read_at IS 'Thời điểm đọc; có giá trị khi và chỉ khi is_read = TRUE.';
COMMENT ON COLUMN notification.created_at IS 'Thời điểm tạo bản ghi (TIMESTAMPTZ, mặc định CURRENT_TIMESTAMP).';
COMMENT ON COLUMN notification.deleted_at IS 'Thời điểm xoá mềm; NULL nghĩa là bản ghi đang hoạt động.';
COMMENT ON COLUMN notification.deleted_by IS 'Tài khoản thực hiện xoá mềm (FK → account).';

-- =============================================================================
-- PHẦN 8: CÁC VIEW THỐNG KÊ
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 8.1. View: v_slot_occupancy_by_floor
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

COMMENT ON VIEW v_slot_occupancy_by_floor IS 'Thống kê sức chứa và mức sử dụng ô đỗ, mỗi dòng là một khu của một tầng (dù tên có chữ "by_floor"). Trạng thái hiệu lực của ô được tính từ phiên đang mở, vé đang hiệu lực và đặt chỗ chưa hết hạn; MAINTENANCE và CHARGING giữ nguyên.';

-- -----------------------------------------------------------------------------
-- 8.2. View: v_revenue_today_by_method
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

COMMENT ON VIEW v_revenue_today_by_method IS 'Thống kê doanh thu hôm nay (CURRENT_DATE) tách tiền mặt và VietQR, kèm tỷ lệ. Gồm mọi chứng từ PAID, kể cả tiền cọc đặt chỗ.';

-- -----------------------------------------------------------------------------
-- 8.3. View: v_traffic_by_hour
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

COMMENT ON VIEW v_traffic_by_hour IS 'Thống kê số lượt xe vào và ra theo từng giờ.';

-- -----------------------------------------------------------------------------
-- 8.4. View: v_ai_recognition_stats
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

COMMENT ON VIEW v_ai_recognition_stats IS 'Thống kê tỷ lệ nhận diện biển số bằng AI so với nhập tay, độ tin cậy AI trung bình và số cổng quét tự động đang bật.';

-- -----------------------------------------------------------------------------
-- 8.5. View: v_customer_status_summary
-- -----------------------------------------------------------------------------
CREATE VIEW v_customer_status_summary AS
SELECT
    COUNT(*)::BIGINT AS total_customers,
    COUNT(*) FILTER (WHERE status = 'ACTIVE')::BIGINT AS active_customers,
    COUNT(*) FILTER (WHERE status = 'SUSPENDED')::BIGINT AS suspended_customers,
    COUNT(*) FILTER (WHERE status = 'BLACKLISTED')::BIGINT AS blacklisted_customers
FROM customer
WHERE deleted_at IS NULL;

COMMENT ON VIEW v_customer_status_summary IS 'Gồm bốn số tổng hợp khách hàng chưa xoá: tổng, ACTIVE, SUSPENDED, BLACKLISTED.';

-- -----------------------------------------------------------------------------
-- 8.6. View: v_revenue_statistics
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

COMMENT ON VIEW v_revenue_statistics IS 'Thống kê doanh thu theo năm, quý, tháng, tách số vé bán và số lần gia hạn. Chỉ cộng ticket.price và ticket_renewal.additional_price; không gồm tiền cọc hay cước theo phiên.';

-- -----------------------------------------------------------------------------
-- 8.7. View: v_vehicle_traffic_daily
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

COMMENT ON VIEW v_vehicle_traffic_daily IS 'Thống kê số lượt vào, ra và số phiên đang đỗ theo từng ngày.';

-- -----------------------------------------------------------------------------
-- 8.8. View: v_customer_vehicle_summary
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

COMMENT ON VIEW v_customer_vehicle_summary IS 'Với mỗi khách chưa xoá: số xe đã đăng ký và số vé đang hiệu lực.';

-- =============================================================================
-- PHẦN 9: ĐẶT CHỖ TRƯỚC (VIEW TỔNG QUAN)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 9.1. View: v_booking_overview
-- Tổng quan các lượt đặt chỗ trước: khách hàng, xe, cấu trúc bãi/tầng/khu/ô
-- và chứng từ tiền cọc.
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

COMMENT ON VIEW v_booking_overview IS 'Bản tổng hợp mọi lượt đặt chỗ: bãi/tầng/khu/ô, khách (hoặc tên khách vãng lai), xe, trạng thái, cọc, chứng từ cọc và các mốc thời gian. Nối LEFT JOIN với payment nên một lượt đặt có nhiều chứng từ sẽ cho nhiều dòng.';

COMMIT;
