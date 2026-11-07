-- =============================================================================
-- FILE: db/01-schema.sql
-- DỰ ÁN: Hệ thống quản lý bãi đỗ xe ô tô (parking_management)
-- CƠ SỞ DỮ LIỆU: PostgreSQL
-- MÔ TẢ:
--   Lược đồ cơ sở dữ liệu quan hệ của hệ thống quản lý bãi đỗ xe ô tô.
--   Bao gồm các bảng, ràng buộc toàn vẹn, chỉ mục, trigger, hàm nghiệp vụ,
--   view phân tích thống kê và chú thích tài liệu hóa cơ sở dữ liệu.
--   Quy ước chung: xoá mềm (deleted_at, deleted_by), khoá lạc quan (row_version)
--   và mọi khoá ngoại đều ON DELETE RESTRICT.
--   Tập lệnh chỉ tạo mới, không có câu lệnh phá huỷ dữ liệu.
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
-- 1.1. Bảng: account (Tài khoản đăng nhập và vai trò)
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
-- 1.2. Bảng: persistent_login_token (Token "ghi nhớ đăng nhập")
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
-- 1.3. Bảng: password_reset_token (Kho token dùng 1 lần cho quên mật khẩu hoặc đặt lại mật khẩu)
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
-- 2.1. Bảng: position (Danh mục chức vụ nhân viên)
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
-- 2.2. Các bảng: administrative_province, administrative_district, administrative_ward (Tỉnh, quận/huyện, phường/xã)
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
-- 2.3. Bảng: employee (Hồ sơ nhân viên)
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
-- 3.1. Bảng: customer (Hồ sơ khách hàng và trạng thái)
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
-- 3.2. Bảng: plate_blacklist (Danh sách đen biển số)
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
-- 3.3. Bảng: vehicle_type (Danh mục loại xe)
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
-- 3.4. Bảng: ticket_type (Bảng giá các loại vé)
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
-- 3.5. Bảng: vehicle (Xe của khách hàng)
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
-- 4.1. Bảng: parking_lot (Bãi đỗ xe)
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
-- 4.1.1. Bảng: booking_policy (Chính sách đặt chỗ của mỗi bãi)
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
-- 4.2. Bảng: parking_floor (Tầng của bãi)
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
-- 4.3. Bảng: parking_zone (Khu trong tầng)
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
-- 4.4. Bảng: parking_slot (Ô đỗ xe)
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
-- 4.5. Bảng: slot_allowed_vehicle_type (Loại xe được phép ở mỗi ô)
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
-- 4.6. Bảng: slot_reservation (Lượt đặt trước ô đỗ)
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
-- 5.1. Bảng: ticket (Vé đã phát hành)
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
-- 5.2. Bảng: ticket_renewal (Lịch sử gia hạn vé)
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
-- 6.1. Bảng: parking_gate (Cổng vào/ra và camera)
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
-- 6.2. Bảng: vehicle_entry_exit_log (Phiên đỗ xe vào/ra)
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
-- 6.3. Bảng: payment (Chứng từ thanh toán)
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
-- 7.1. Bảng: activity_log (Nhật ký hoạt động)
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
-- 7.2. Bảng: system_alert (Cảnh báo hệ thống)
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
-- 7.3. Bảng: news (Tin tức)
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
-- 7.4. Bảng: notification (Thông báo)
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
-- PHẦN 8: TRIGGER VÀ CÁC HÀM ĐỒNG BỘ
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 8.1. Hàm trigger: fn_update_row_version_and_timestamp()
-- Tự động tăng row_version và cập nhật updated_at trên các bảng có quản lý phiên bản.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_update_row_version_and_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    NEW.row_version := OLD.row_version + 1;
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_update_row_version_and_timestamp() IS 'Tự động tăng row_version và gán updated_at = CURRENT_TIMESTAMP khi BEFORE UPDATE trên các bảng có quản lý phiên bản.';

CREATE TRIGGER trg_account_row_version
    BEFORE UPDATE ON account
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_position_row_version
    BEFORE UPDATE ON position
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_employee_row_version
    BEFORE UPDATE ON employee
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_customer_row_version
    BEFORE UPDATE ON customer
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_plate_blacklist_row_version
    BEFORE UPDATE ON plate_blacklist
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_vehicle_type_row_version
    BEFORE UPDATE ON vehicle_type
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_ticket_type_row_version
    BEFORE UPDATE ON ticket_type
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_vehicle_row_version
    BEFORE UPDATE ON vehicle
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_parking_lot_row_version
    BEFORE UPDATE ON parking_lot
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_booking_policy_row_version
    BEFORE UPDATE ON booking_policy
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_parking_floor_row_version
    BEFORE UPDATE ON parking_floor
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_parking_zone_row_version
    BEFORE UPDATE ON parking_zone
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_parking_slot_row_version
    BEFORE UPDATE ON parking_slot
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_slot_reservation_row_version
    BEFORE UPDATE ON slot_reservation
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_ticket_row_version
    BEFORE UPDATE ON ticket
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_parking_gate_row_version
    BEFORE UPDATE ON parking_gate
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_payment_row_version
    BEFORE UPDATE ON payment
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

CREATE TRIGGER trg_news_row_version
    BEFORE UPDATE ON news
    FOR EACH ROW EXECUTE FUNCTION fn_update_row_version_and_timestamp();

-- -----------------------------------------------------------------------------
-- 8.2. Hàm trigger: fn_guard_parking_slot_status()
-- Kiểm soát các chuyển đổi trạng thái của parking_slot.status:
--   - Không thể đặt AVAILABLE khi đang có phiên đỗ mở, đặt chỗ hiệu lực hoặc vé hiệu lực.
--   - OCCUPIED chỉ được thiết lập theo phiên đỗ đang mở trong vehicle_entry_exit_log.
--   - Không thể đặt MAINTENANCE hoặc RESERVED khi đang có xe đỗ thực tế trong ô.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_parking_slot_status()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_has_open_session BOOLEAN;
    v_has_active_reservation BOOLEAN;
    v_has_active_ticket BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'OCCUPIED' THEN
            RAISE EXCEPTION 'Không thể chuyển vị trí sang trạng thái đang có xe khi không có phiên đỗ xe đang mở.'
                USING ERRCODE = 'check_violation',
                      HINT = 'OCCUPIED status requires an open session in vehicle_entry_exit_log (TL-03, OQ-81).';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NEW;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM vehicle_entry_exit_log l
        WHERE l.slot_id = NEW.id
          AND l.exit_time IS NULL
    ) INTO v_has_open_session;

    IF NEW.status = 'OCCUPIED' AND NOT v_has_open_session THEN
        RAISE EXCEPTION 'Không thể chuyển vị trí sang trạng thái đang có xe khi không có phiên đỗ xe đang mở.'
            USING ERRCODE = 'check_violation',
                  HINT = 'OCCUPIED status only follows an open session (TL-03, OQ-81).';
    END IF;

    IF NEW.status IN ('MAINTENANCE', 'RESERVED') AND v_has_open_session THEN
        RAISE EXCEPTION 'Không thể chuyển trạng thái vị trí khi đang có xe đỗ trong ô.'
            USING ERRCODE = 'check_violation',
                  HINT = 'Close the open parking session before marking the slot as RESERVED or MAINTENANCE (TL-03, OQ-81).';
    END IF;

    IF NEW.status = 'AVAILABLE' THEN
        SELECT EXISTS (
            SELECT 1
            FROM slot_reservation r
            WHERE r.slot_id = NEW.id
              AND r.deleted_at IS NULL
              AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED')
              AND r.reserved_until > CURRENT_TIMESTAMP
        ) INTO v_has_active_reservation;

        SELECT EXISTS (
            SELECT 1
            FROM ticket t
            WHERE t.slot_id = NEW.id
              AND t.deleted_at IS NULL
              AND t.status IN ('ACTIVE', 'RENEWING')
              AND CURRENT_TIMESTAMP >= t.effective_from
              AND CURRENT_TIMESTAMP < t.effective_to
        ) INTO v_has_active_ticket;

        IF v_has_open_session OR v_has_active_reservation OR v_has_active_ticket THEN
            RAISE EXCEPTION 'Không thể đánh dấu vị trí trống khi đang có xe đỗ hoặc đặt trước còn hiệu lực.'
                USING ERRCODE = 'check_violation',
                      HINT = 'Cannot mark slot AVAILABLE while an open session, active reservation, or active ticket exists (TL-03, OQ-81).';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_guard_parking_slot_status() IS 'Kiểm soát chuyển đổi parking_slot.status: OCCUPIED chỉ đi kèm phiên đỗ đang mở và không thể chuyển sang AVAILABLE khi còn phiên đỗ, đặt chỗ hoặc vé đang hiệu lực.';

CREATE TRIGGER trg_guard_parking_slot_status
    BEFORE INSERT OR UPDATE OF status ON parking_slot
    FOR EACH ROW EXECUTE FUNCTION fn_guard_parking_slot_status();

-- -----------------------------------------------------------------------------
-- 8.3. Hàm trigger: fn_sync_ticket_status()
-- Đồng bộ trạng thái vé theo mốc thời gian effective_to và kiểm tra tính hợp lệ của ô đỗ.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_sync_ticket_status()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_slot_status VARCHAR(20);
BEGIN
    IF NEW.status IN ('ACTIVE', 'RENEWING') AND NEW.effective_to <= CURRENT_TIMESTAMP THEN
        NEW.status := 'EXPIRED';
    ELSIF TG_OP = 'UPDATE'
      AND NEW.status IN ('EXPIRED', 'RENEWING')
      AND NEW.effective_to > CURRENT_TIMESTAMP
      AND OLD.effective_to <= CURRENT_TIMESTAMP THEN
        NEW.status := 'ACTIVE';
    END IF;

    IF NEW.deleted_at IS NULL AND NEW.status IN ('ACTIVE', 'RENEWING') AND NEW.effective_to > CURRENT_TIMESTAMP THEN
        SELECT s.status INTO v_slot_status
        FROM parking_slot s
        WHERE s.id = NEW.slot_id
          AND s.deleted_at IS NULL
        FOR NO KEY UPDATE;

        IF v_slot_status = 'MAINTENANCE' THEN
            RAISE EXCEPTION 'Vị trí này đang bảo trì.'
                USING ERRCODE = 'check_violation',
                      HINT = 'Cannot assign an active ticket to a slot in MAINTENANCE status (PROP-4.5.2-P01, TL-03, TL-10).';
        END IF;

        -- Kiểm tra loại xe vehicle_type_id có được phép đỗ theo slot_allowed_vehicle_type
        IF NEW.slot_id IS NOT NULL AND NEW.vehicle_id IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1 FROM slot_allowed_vehicle_type savt
                JOIN vehicle v ON v.id = NEW.vehicle_id
                WHERE savt.slot_id = NEW.slot_id AND savt.vehicle_type_id = v.vehicle_type_id
            ) THEN
                RAISE EXCEPTION 'Loại xe không phù hợp với cấu hình cho phép của vị trí đỗ.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Vehicle type is not permitted in the assigned parking slot (PROP-SLOT-VEHICLE-TYPE-MISMATCH, TL-38).';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_sync_ticket_status() IS 'Tự động chuyển trạng thái vé sang EXPIRED khi effective_to <= CURRENT_TIMESTAMP, kích hoạt lại khi gia hạn, chặn gán vào ô MAINTENANCE và kiểm tra tương thích loại xe cho phép.';

CREATE TRIGGER trg_ticket_status_sync
    BEFORE INSERT OR UPDATE ON ticket
    FOR EACH ROW EXECUTE FUNCTION fn_sync_ticket_status();

-- -----------------------------------------------------------------------------
-- 8.4. Hàm trigger: fn_guard_slot_reservation_write()
-- Bảo vệ ghi dữ liệu slot_reservation: chặn ô MAINTENANCE, vé trùng lịch, khách hoặc xe bị cấm và sai loại xe.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_slot_reservation_write()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_slot_status VARCHAR(20);
    v_has_conflicting_ticket BOOLEAN;
BEGIN
    -- Từ chối đặt chỗ có thời gian bắt đầu trong quá khứ khi tạo ở trạng thái PENDING_PAYMENT
    IF NEW.status = 'PENDING_PAYMENT' AND NEW.reserved_from < CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Thời gian bắt đầu đặt chỗ không được ở trong quá khứ.'
            USING ERRCODE = 'check_violation',
                  HINT = 'PROP-BOOK-RESERVE-IN-PAST';
    END IF;

    -- Từ chối đặt chỗ đang hoạt động có khoảng thời gian đã kết thúc trong quá khứ
    IF NEW.status IN ('PENDING_PAYMENT', 'CONFIRMED') AND NEW.reserved_until <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Thời gian kết thúc đặt chỗ không được ở trong quá khứ.'
            USING ERRCODE = 'check_violation',
                  HINT = 'PROP-BOOK-RESERVE-IN-PAST';
    END IF;


    IF NEW.deleted_at IS NULL AND NEW.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN') THEN
        SELECT s.status INTO v_slot_status
        FROM parking_slot s
        WHERE s.id = NEW.slot_id
          AND s.deleted_at IS NULL
        FOR NO KEY UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Vị trí đỗ xe không tồn tại hoặc đã bị xóa.'
                USING ERRCODE = 'check_violation';
        END IF;

        IF v_slot_status = 'MAINTENANCE' THEN
            RAISE EXCEPTION 'Vị trí này đang bảo trì.'
                USING ERRCODE = 'check_violation',
                      HINT = 'Cannot reserve a slot currently in MAINTENANCE status (PROP-4.5.2-P01, TL-03, TL-04).';
        END IF;

        -- Kiểm tra trạng thái khách hàng
        IF NEW.customer_id IS NOT NULL THEN
            IF EXISTS (
                SELECT 1 FROM customer c
                WHERE c.id = NEW.customer_id
                  AND c.deleted_at IS NULL
                  AND c.status IN ('BLACKLISTED', 'SUSPENDED')
            ) THEN
                RAISE EXCEPTION 'Khách hàng đang ở trạng thái khóa hoặc danh sách đen, không được phép đặt chỗ trước.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-BOOK-CUSTOMER-BLACKLISTED';
            END IF;
        END IF;

        -- Kiểm tra danh sách đen của phương tiện
        IF NEW.vehicle_id IS NOT NULL THEN
            IF EXISTS (
                SELECT 1 FROM plate_blacklist pb
                JOIN vehicle v ON v.id = NEW.vehicle_id
                WHERE (pb.license_plate = v.license_plate_norm OR fn_normalize_license_plate(pb.license_plate) = v.license_plate_norm)
                  AND pb.is_active = TRUE
                  AND pb.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'Phương tiện nằm trong danh sách đen, không được phép đặt chỗ.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-BOOK-PLATE-BLACKLISTED';
            END IF;
        END IF;

        SELECT EXISTS (
            SELECT 1
            FROM ticket t
            WHERE t.slot_id = NEW.slot_id
              AND t.deleted_at IS NULL
              AND t.status IN ('ACTIVE', 'RENEWING')
              AND tstzrange(t.effective_from, t.effective_to, '[)') && tstzrange(NEW.reserved_from, NEW.reserved_until, '[)')
              AND (NEW.vehicle_id IS NULL OR t.vehicle_id <> NEW.vehicle_id)
        ) INTO v_has_conflicting_ticket;

        IF v_has_conflicting_ticket THEN
            RAISE EXCEPTION 'Vị trí này đã có xe đk vé và đang sử dụng'
                USING ERRCODE = 'check_violation',
                      HINT = 'Slot is already reserved by an active subscription ticket during the requested window (MSG-4.5.2-M02, TL-04).';
        END IF;

        -- Kiểm tra loại xe vehicle_type_id có được phép đỗ theo slot_allowed_vehicle_type
        IF NEW.vehicle_id IS NOT NULL AND NEW.slot_id IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1 FROM slot_allowed_vehicle_type savt
                JOIN vehicle v ON v.id = NEW.vehicle_id
                WHERE savt.slot_id = NEW.slot_id AND savt.vehicle_type_id = v.vehicle_type_id
            ) THEN
                RAISE EXCEPTION 'Loại xe không phù hợp với cấu hình cho phép của vị trí đỗ.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Vehicle type is not permitted in the assigned parking slot (PROP-SLOT-VEHICLE-TYPE-MISMATCH, TL-38).';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_guard_slot_reservation_write() IS 'Ngăn tạo slot_reservation trên ô MAINTENANCE, trùng vé đang hiệu lực, khách hàng hoặc xe trong danh sách đen, hoặc không đúng loại xe cho phép.';

CREATE TRIGGER trg_guard_slot_reservation_write
    BEFORE INSERT OR UPDATE ON slot_reservation
    FOR EACH ROW EXECUTE FUNCTION fn_guard_slot_reservation_write();

-- -----------------------------------------------------------------------------
-- 8.5. Hàm trigger: fn_guard_slot_reservation_on_entry()
-- Kiểm soát khi xe vào bãi trong vehicle_entry_exit_log:
--   1. Khi thêm phiên hoặc đổi biển số có vehicle_id IS NULL,
--      và biển số chuẩn hoá khớp với xe đăng ký còn hoạt động,
--      tự động gán NEW.vehicle_id cho xe đó.
--   2. Khi phiên mở (exit_time IS NULL) có vehicle_id IS NOT NULL lúc INSERT
--      hoặc khi đổi biển số/vehicle_id, biển số chuẩn hoá phải khớp với
--      xe đã đăng ký đang hoạt động (nếu không khớp sẽ báo lỗi dữ liệu).
--   3. Từ chối cho xe vào các ô đỗ đang bảo trì MAINTENANCE.
--   4. Từ chối cho xe vào ô đỗ đã có vé đang hiệu lực của xe khác
--      với thông báo vị trí đã có xe đăng ký vé và đang sử dụng.
--   5. Từ chối cho xe vào ô đỗ đã được đặt chỗ trước bởi phương tiện khác.
--   6. Kiểm tra vehicle_type_id theo slot_allowed_vehicle_type và khoá
--      parking_slot trước khi thay đổi vehicle_entry_exit_log để bảo đảm thứ tự khoá an toàn.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_slot_reservation_on_entry()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_slot_status VARCHAR(20);
    v_lot_id BIGINT;
    v_registered_plate VARCHAR(20);
    v_norm_new_plate TEXT;
    v_reserved_ticket_vehicle_id BIGINT;
    v_reserved_ticket_plate_norm TEXT;
    v_res_id BIGINT;
    v_res_veh_id BIGINT;
    v_res_plate_norm TEXT;
    v_res_from TIMESTAMPTZ;
    v_res_until TIMESTAMPTZ;
    v_early_min INTEGER;
    v_grace_min INTEGER;
    v_is_owner BOOLEAN;
BEGIN
    v_norm_new_plate := fn_normalize_license_plate(NEW.license_plate);

    -- 1. Tự động liên kết biển số vãng lai: nếu vehicle_id IS NULL khi INSERT hoặc đổi biển số/vehicle_id,
    --    và biển số chuẩn hoá khớp với xe đã đăng ký còn hoạt động, tự động gán NEW.vehicle_id.
    IF NEW.vehicle_id IS NULL AND (
        TG_OP = 'INSERT'
        OR NEW.license_plate IS DISTINCT FROM OLD.license_plate
        OR NEW.vehicle_id IS DISTINCT FROM OLD.vehicle_id
    ) THEN
        SELECT v.id INTO NEW.vehicle_id
        FROM vehicle v
        WHERE v.license_plate_norm = v_norm_new_plate
          AND v.deleted_at IS NULL
        LIMIT 1;
    END IF;

    IF NEW.exit_time IS NULL THEN
        -- 2. Nếu có vehicle_id khi INSERT hoặc khi đổi biển số/vehicle_id trên phiên đang mở,
        --    xác thực biển số chuẩn hoá phải khớp với xe đã đăng ký còn hoạt động.
        --    Không chạy khi đóng phiên (NEW.exit_time IS NOT NULL) để xe đã xoá mềm vẫn có thể ra.
        IF NEW.vehicle_id IS NOT NULL AND (
            TG_OP = 'INSERT'
            OR NEW.license_plate IS DISTINCT FROM OLD.license_plate
            OR NEW.vehicle_id IS DISTINCT FROM OLD.vehicle_id
        ) THEN
            SELECT v.license_plate INTO v_registered_plate
            FROM vehicle v
            WHERE v.id = NEW.vehicle_id
              AND v.deleted_at IS NULL;

            IF NOT FOUND OR v_norm_new_plate <> fn_normalize_license_plate(v_registered_plate) THEN
                RAISE EXCEPTION 'Lỗi dữ liệu không tìm thấy đê lưu'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Entered license plate does not match the registered active vehicle (MSG-4.5.1-M02, TL-05, OQ-75).';
            END IF;
        END IF;

        -- 3. Nếu có slot_id, kiểm tra ô bảo trì, vé đang hiệu lực và đặt chỗ trước
        IF NEW.slot_id IS NOT NULL THEN
            SELECT s.status, pf.lot_id INTO v_slot_status, v_lot_id
            FROM parking_slot s
            JOIN parking_zone pz ON pz.id = s.zone_id
            JOIN parking_floor pf ON pf.id = pz.floor_id
            WHERE s.id = NEW.slot_id
              AND s.deleted_at IS NULL
            FOR NO KEY UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'Vị trí đỗ xe không tồn tại hoặc đã bị xóa.'
                    USING ERRCODE = 'check_violation';
            END IF;

            IF v_slot_status = 'MAINTENANCE' THEN
                RAISE EXCEPTION 'Vị trí này đang bảo trì.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Slot is currently under maintenance and cannot be occupied (PROP-4.5.2-P01, OQ-63, OQ-67, TL-03).';
            END IF;

            -- Kiểm tra loại xe vehicle_type_id có được phép đỗ theo slot_allowed_vehicle_type
            IF NEW.vehicle_id IS NOT NULL THEN
                IF NOT EXISTS (
                    SELECT 1 FROM slot_allowed_vehicle_type savt
                    JOIN vehicle v ON v.id = NEW.vehicle_id
                    WHERE savt.slot_id = NEW.slot_id AND savt.vehicle_type_id = v.vehicle_type_id
                ) THEN
                    RAISE EXCEPTION 'Loại xe không phù hợp với cấu hình cho phép của vị trí đỗ.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Vehicle type is not permitted in the assigned parking slot (PROP-SLOT-VEHICLE-TYPE-MISMATCH, TL-38).';
                END IF;
            END IF;

            SELECT t.vehicle_id, v.license_plate_norm
            INTO v_reserved_ticket_vehicle_id, v_reserved_ticket_plate_norm
            FROM ticket t
            JOIN vehicle v ON v.id = t.vehicle_id
            WHERE t.slot_id = NEW.slot_id
              AND t.deleted_at IS NULL
              AND t.status IN ('ACTIVE', 'RENEWING')
              AND CURRENT_TIMESTAMP >= t.effective_from
              AND CURRENT_TIMESTAMP < t.effective_to
            ORDER BY t.effective_to DESC, t.id DESC
            LIMIT 1;

            IF v_reserved_ticket_vehicle_id IS NOT NULL THEN
                IF (NEW.vehicle_id IS NOT NULL AND NEW.vehicle_id <> v_reserved_ticket_vehicle_id)
                   OR (v_norm_new_plate <> v_reserved_ticket_plate_norm) THEN
                    RAISE EXCEPTION 'Vị trí này đã có xe đk vé và đang sử dụng'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Slot is reserved by an active ticket for another vehicle (MSG-4.5.2-M02, TL-04, TL-05, OQ-67).';
                END IF;
            END IF;

            -- 4. Xử lý đặt chỗ trước (liên kết đặt chỗ và chuyển trạng thái CHECKED_IN)
            SELECT r.id, r.vehicle_id, rv.license_plate_norm, r.reserved_from, r.reserved_until,
                   COALESCE(bp.early_checkin_minutes, 15),
                   COALESCE(bp.grace_minutes, 15)
            INTO v_res_id, v_res_veh_id, v_res_plate_norm, v_res_from, v_res_until,
                 v_early_min, v_grace_min
            FROM slot_reservation r
            LEFT JOIN vehicle rv ON rv.id = r.vehicle_id
            LEFT JOIN booking_policy bp ON bp.lot_id = v_lot_id AND bp.deleted_at IS NULL
            WHERE r.slot_id = NEW.slot_id
              AND r.deleted_at IS NULL
              AND r.status = 'CONFIRMED'
              AND CURRENT_TIMESTAMP < r.reserved_until
              AND CURRENT_TIMESTAMP >= (r.reserved_from - (COALESCE(bp.early_checkin_minutes, 15) * INTERVAL '1 minute') - INTERVAL '2 hours')
            ORDER BY r.reserved_from ASC
            LIMIT 1;

            IF v_res_id IS NOT NULL THEN
                v_is_owner := (
                    (NEW.reservation_id IS NOT NULL AND NEW.reservation_id = v_res_id)
                    OR (v_res_veh_id IS NOT NULL AND NEW.vehicle_id IS NOT NULL AND NEW.vehicle_id = v_res_veh_id)
                    OR (v_res_plate_norm IS NOT NULL AND v_norm_new_plate = v_res_plate_norm)
                );

                IF v_is_owner THEN
                    IF CURRENT_TIMESTAMP < (v_res_from - (v_early_min * INTERVAL '1 minute')) THEN
                        RAISE EXCEPTION 'Chưa đến thời gian nhận vị trí đỗ xe đã đặt trước.'
                            USING ERRCODE = 'check_violation',
                                  HINT = 'PROP-BOOK-ENTRY-EARLY';
                    END IF;

                    IF CURRENT_TIMESTAMP > (v_res_from + (v_grace_min * INTERVAL '1 minute')) THEN
                        RAISE EXCEPTION 'Lượt đặt trước đã bị hủy do quá thời gian ân hạn nhận chỗ.'
                            USING ERRCODE = 'check_violation',
                                  HINT = 'PROP-BOOK-ENTRY-LATE';
                    END IF;

                    NEW.reservation_id := v_res_id;
                    UPDATE slot_reservation
                    SET status = 'CHECKED_IN',
                        checked_in_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = v_res_id
                      AND status = 'CONFIRMED'
                      AND deleted_at IS NULL;
                ELSE
                    IF CURRENT_TIMESTAMP >= (v_res_from - (v_early_min * INTERVAL '1 minute'))
                       AND CURRENT_TIMESTAMP < v_res_until THEN
                        RAISE EXCEPTION 'Vị trí này đã được đặt trước cho phương tiện khác.'
                            USING ERRCODE = 'check_violation',
                                  HINT = 'Slot has an active reservation for another vehicle (PROP-4.5.2-P05, TL-04, OQ-81).';
                    END IF;
                END IF;
            ELSE
                IF EXISTS (
                    SELECT 1
                    FROM slot_reservation r
                    WHERE r.slot_id = NEW.slot_id
                      AND r.deleted_at IS NULL
                      AND r.status IN ('PENDING_PAYMENT', 'CHECKED_IN')
                      AND CURRENT_TIMESTAMP < r.reserved_until
                      AND (NEW.reservation_id IS NULL OR r.id <> NEW.reservation_id)
                ) THEN
                    RAISE EXCEPTION 'Vị trí này đã được đặt trước cho phương tiện khác.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Slot has an active reservation for another vehicle (PROP-4.5.2-P05, TL-04, OQ-81).';
                END IF;
            END IF;
        END IF;
    ELSIF COALESCE(NEW.slot_id, OLD.slot_id) IS NOT NULL THEN
        -- Khoá ô đỗ trong trigger BEFORE lúc xe ra để đảm bảo cả vào và ra
        -- luôn khoá parking_slot trước khi thay đổi vehicle_entry_exit_log (thứ tự khoá an toàn).
        PERFORM 1
        FROM parking_slot s
        WHERE s.id = COALESCE(NEW.slot_id, OLD.slot_id)
          AND s.deleted_at IS NULL
        FOR NO KEY UPDATE;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_guard_slot_reservation_on_entry() IS 'Xác thực phiên xe vào qua barrier: tự liên kết xe khách, chặn ô MAINTENANCE, kiểm tra loại xe, liên kết đặt chỗ và chuyển CHECKED_IN, bảo vệ ô đã đặt trước không cho xe lạ vào.';

CREATE TRIGGER trg_guard_slot_reservation_on_entry
    BEFORE INSERT OR UPDATE OF slot_id, exit_time, vehicle_id, license_plate ON vehicle_entry_exit_log
    FOR EACH ROW EXECUTE FUNCTION fn_guard_slot_reservation_on_entry();

-- -----------------------------------------------------------------------------
-- 8.6. Hàm bổ trợ: fn_recompute_slot_status(p_slot_id BIGINT)
-- Tính toán lại trạng thái ô đỗ từ các phiên đang mở, vé đang hiệu lực và đặt chỗ trước.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_recompute_slot_status(p_slot_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_has_open_session BOOLEAN;
    v_has_active_reservation BOOLEAN;
    v_current_status VARCHAR(20);
BEGIN
    IF p_slot_id IS NULL THEN
        RETURN;
    END IF;

    SELECT s.status INTO v_current_status
    FROM parking_slot s
    WHERE s.id = p_slot_id
      AND s.deleted_at IS NULL
    FOR UPDATE;

    IF NOT FOUND OR v_current_status = 'MAINTENANCE' THEN
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM vehicle_entry_exit_log l
        WHERE l.slot_id = p_slot_id
          AND l.exit_time IS NULL
    ) INTO v_has_open_session;

    IF v_has_open_session THEN
        IF v_current_status NOT IN ('OCCUPIED', 'CHARGING') THEN
            UPDATE parking_slot
            SET status = 'OCCUPIED'
            WHERE id = p_slot_id
              AND deleted_at IS NULL;
        END IF;
        RETURN;
    END IF;

    SELECT (
        EXISTS (
            SELECT 1
            FROM ticket t
            WHERE t.slot_id = p_slot_id
              AND t.deleted_at IS NULL
              AND t.status IN ('ACTIVE', 'RENEWING')
              AND CURRENT_TIMESTAMP >= t.effective_from
              AND CURRENT_TIMESTAMP < t.effective_to
        )
        OR EXISTS (
            SELECT 1
            FROM slot_reservation r
            WHERE r.slot_id = p_slot_id
              AND r.deleted_at IS NULL
              AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED')
              AND r.reserved_until > CURRENT_TIMESTAMP
        )
    ) INTO v_has_active_reservation;

    IF v_has_active_reservation THEN
        IF v_current_status <> 'RESERVED' THEN
            UPDATE parking_slot
            SET status = 'RESERVED'
            WHERE id = p_slot_id
              AND deleted_at IS NULL;
        END IF;
    ELSE
        IF v_current_status <> 'AVAILABLE' THEN
            UPDATE parking_slot
            SET status = 'AVAILABLE'
            WHERE id = p_slot_id
              AND deleted_at IS NULL;
        END IF;
    END IF;
END;
$$;

COMMENT ON FUNCTION fn_recompute_slot_status(BIGINT) IS 'Đồng bộ parking_slot.status (OCCUPIED, RESERVED, AVAILABLE) từ phiên đỗ đang mở, vé hiệu lực và đặt chỗ đang giữ, giữ nguyên trạng thái MAINTENANCE.';

-- -----------------------------------------------------------------------------
-- 8.7. Hàm trigger: fn_sync_slot_status_on_traffic()
-- Đồng bộ trạng thái parking_slot.status và hoàn tất đặt chỗ liên kết khi thay đổi vehicle_entry_exit_log.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_sync_slot_status_on_traffic()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.slot_id IS NOT NULL AND OLD.slot_id IS DISTINCT FROM NEW.slot_id THEN
        PERFORM fn_recompute_slot_status(OLD.slot_id);
    END IF;

    -- Tự động hoàn tất đặt chỗ liên kết khi phiên đỗ xe hoàn tất thanh toán và rời bãi
    IF TG_OP = 'UPDATE' AND OLD.exit_time IS NULL AND NEW.exit_time IS NOT NULL AND NEW.reservation_id IS NOT NULL THEN
        UPDATE slot_reservation
        SET status = 'COMPLETED',
            completed_at = NEW.exit_time,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.reservation_id
          AND status = 'CHECKED_IN'
          AND deleted_at IS NULL;
    END IF;

    IF NEW.slot_id IS NOT NULL THEN
        PERFORM fn_recompute_slot_status(NEW.slot_id);
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_sync_slot_status_on_traffic() IS 'Hàm trigger cập nhật parking_slot.status khi xe vào bãi, ra bãi hoặc chuyển đổi vị trí ô đỗ.';

CREATE TRIGGER trg_slot_status_on_traffic
    AFTER INSERT OR UPDATE ON vehicle_entry_exit_log
    FOR EACH ROW EXECUTE FUNCTION fn_sync_slot_status_on_traffic();

-- -----------------------------------------------------------------------------
-- 8.8. Hàm trigger: fn_sync_slot_status_on_ticket()
-- Đồng bộ parking_slot.status và thông tin vé hiệu lực của xe sau khi
-- INSERT hoặc UPDATE trên bảng ticket.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_sync_slot_status_on_ticket()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_latest_type_id BIGINT;
    v_latest_expires_at TIMESTAMPTZ;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.slot_id IS DISTINCT FROM NEW.slot_id THEN
        PERFORM fn_recompute_slot_status(OLD.slot_id);
    END IF;

    PERFORM fn_recompute_slot_status(NEW.slot_id);

    SELECT t.ticket_type_id, t.effective_to
    INTO v_latest_type_id, v_latest_expires_at
    FROM ticket t
    WHERE t.vehicle_id = NEW.vehicle_id
      AND t.deleted_at IS NULL
      AND t.status IN ('ACTIVE', 'RENEWING')
      AND t.effective_to > CURRENT_TIMESTAMP
    ORDER BY t.effective_to DESC, t.id DESC
    LIMIT 1;

    UPDATE vehicle
    SET ticket_type_id = v_latest_type_id,
        ticket_expires_at = v_latest_expires_at
    WHERE id = NEW.vehicle_id
      AND (ticket_type_id IS DISTINCT FROM v_latest_type_id
           OR ticket_expires_at IS DISTINCT FROM v_latest_expires_at);

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_sync_slot_status_on_ticket() IS 'Đồng bộ trạng thái ô đỗ và thông tin vé trên xe (ticket_type_id, ticket_expires_at) theo vòng đời của vé.';

CREATE TRIGGER trg_slot_status_on_ticket
    AFTER INSERT OR UPDATE ON ticket
    FOR EACH ROW EXECUTE FUNCTION fn_sync_slot_status_on_ticket();

-- -----------------------------------------------------------------------------
-- 8.9. Hàm trigger: fn_sync_slot_status_on_reservation()
-- Đồng bộ parking_slot.status sau khi INSERT hoặc UPDATE trên bảng slot_reservation.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_sync_slot_status_on_reservation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.slot_id IS DISTINCT FROM NEW.slot_id THEN
        PERFORM fn_recompute_slot_status(OLD.slot_id);
    END IF;

    PERFORM fn_recompute_slot_status(NEW.slot_id);

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_sync_slot_status_on_reservation() IS 'Đồng bộ parking_slot.status khi đặt chỗ trước được tạo, cập nhật, huỷ, hết hạn hoặc bị xoá mềm.';

CREATE TRIGGER trg_slot_status_on_reservation
    AFTER INSERT OR UPDATE ON slot_reservation
    FOR EACH ROW EXECUTE FUNCTION fn_sync_slot_status_on_reservation();

-- -----------------------------------------------------------------------------
-- 8.10. Hàm trigger: fn_prevent_activity_log_mutation()
-- Bảo đảm tính bất biến chỉ ghi thêm (append-only) trên bảng activity_log.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_prevent_activity_log_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Nhật ký hoạt động là bảng chỉ ghi (append-only), không cho phép cập nhật hoặc xóa.'
        USING ERRCODE = 'check_violation',
              HINT = 'activity_log is strictly append-only (TL-12, OQ-81).';
END;
$$;

COMMENT ON FUNCTION fn_prevent_activity_log_mutation() IS 'Thực thi quy tắc chỉ ghi thêm trên activity_log bằng cách từ chối mọi thao tác UPDATE và DELETE.';

CREATE TRIGGER trg_activity_log_immutable
    BEFORE UPDATE OR DELETE ON activity_log
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_activity_log_mutation();

-- -----------------------------------------------------------------------------
-- 8.11. Hàm trigger: fn_guard_hard_immutable_table()
-- Thực thi tính bất biến tuyệt đối cho các bảng tài chính, kiểm toán, token và danh mục:
-- nghiêm cấm hoàn toàn hành vi xoá cứng hoặc dọn dẹp dữ liệu trong mọi trường hợp.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_hard_immutable_table()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Bảng % là dữ liệu bất biến (chứng từ tài chính / kiểm toán an ninh / danh mục chuẩn), nghiêm cấm xóa vĩnh viễn (hard delete) dưới mọi hình thức.', TG_TABLE_NAME
        USING ERRCODE = '55000',
              HINT = 'Fiscal vouchers, audit movement records, and system reference tables can never be hard-deleted or purged (TL-24, ADR-0003).';
END;
$$;

COMMENT ON FUNCTION fn_guard_hard_immutable_table() IS 'Thực thi tính bất biến tuyệt đối trên chứng từ tài chính, bảng kiểm toán và bảng hệ thống bằng cách từ chối mọi thao tác DELETE.';

CREATE TRIGGER trg_guard_ticket_immutable
    BEFORE DELETE ON ticket
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

CREATE TRIGGER trg_guard_ticket_renewal_immutable
    BEFORE DELETE ON ticket_renewal
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

CREATE TRIGGER trg_guard_payment_immutable
    BEFORE DELETE ON payment
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

CREATE TRIGGER trg_guard_entry_exit_log_immutable
    BEFORE DELETE ON vehicle_entry_exit_log
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

CREATE TRIGGER trg_guard_system_alert_immutable
    BEFORE DELETE ON system_alert
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

CREATE TRIGGER trg_guard_province_immutable
    BEFORE DELETE ON administrative_province
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

CREATE TRIGGER trg_guard_district_immutable
    BEFORE DELETE ON administrative_district
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

CREATE TRIGGER trg_guard_ward_immutable
    BEFORE DELETE ON administrative_ward
    FOR EACH ROW EXECUTE FUNCTION fn_guard_hard_immutable_table();

-- -----------------------------------------------------------------------------
-- 8.12. Hàm trigger: fn_guard_slot_allowed_vehicle_type_delete()
-- Chặn gỡ bỏ loại xe cho phép khỏi ô đỗ khi đang có vé hiệu lực,
-- phiên đỗ mở hoặc đặt chỗ hiệu lực thuộc loại xe đó trong ô.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_slot_allowed_vehicle_type_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- 1. Kiểm tra vé đang hiệu lực hoặc đang gia hạn
    IF EXISTS (
        SELECT 1 FROM ticket t
        JOIN vehicle v ON v.id = t.vehicle_id
        WHERE t.slot_id = OLD.slot_id
          AND v.vehicle_type_id = OLD.vehicle_type_id
          AND t.deleted_at IS NULL
          AND t.status IN ('ACTIVE', 'RENEWING')
          AND t.effective_to > CURRENT_TIMESTAMP
    ) THEN
        RAISE EXCEPTION 'Không thể xóa loại xe cho phép khi vị trí đỗ đang có vé, phiên đỗ hoặc đặt chỗ thuộc loại xe này.'
            USING ERRCODE = 'check_violation',
                  HINT = 'Active ticket uses this vehicle type in this slot (PROP-DEL-SAVT-IN-USE, TL-37).';
    END IF;

    -- 2. Kiểm tra phiên đỗ đang mở
    IF EXISTS (
        SELECT 1 FROM vehicle_entry_exit_log l
        JOIN vehicle v ON v.id = l.vehicle_id
        WHERE l.slot_id = OLD.slot_id
          AND v.vehicle_type_id = OLD.vehicle_type_id
          AND l.exit_time IS NULL
    ) THEN
        RAISE EXCEPTION 'Không thể xóa loại xe cho phép khi vị trí đỗ đang có vé, phiên đỗ hoặc đặt chỗ thuộc loại xe này.'
            USING ERRCODE = 'check_violation',
                  HINT = 'Open session uses this vehicle type in this slot (PROP-DEL-SAVT-IN-USE, TL-37).';
    END IF;

    -- 3. Kiểm tra đặt chỗ đang hiệu lực
    IF EXISTS (
        SELECT 1 FROM slot_reservation r
        JOIN vehicle v ON v.id = r.vehicle_id
        WHERE r.slot_id = OLD.slot_id
          AND v.vehicle_type_id = OLD.vehicle_type_id
          AND r.deleted_at IS NULL
          AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN')
          AND r.reserved_until > CURRENT_TIMESTAMP
    ) THEN
        RAISE EXCEPTION 'Không thể xóa loại xe cho phép khi vị trí đỗ đang có vé, phiên đỗ hoặc đặt chỗ thuộc loại xe này.'
            USING ERRCODE = 'check_violation',
                  HINT = 'Active reservation uses this vehicle type in this slot (PROP-DEL-SAVT-IN-USE, TL-37).';
    END IF;

    RETURN OLD;
END;
$$;

COMMENT ON FUNCTION fn_guard_slot_allowed_vehicle_type_delete() IS 'Chặn gỡ bỏ loại xe cho phép khỏi ô đỗ nếu đang có vé hiệu lực, phiên đỗ mở hoặc đặt chỗ hiệu lực của loại xe đó trong ô.';

CREATE TRIGGER trg_guard_slot_allowed_vehicle_type_delete
    BEFORE DELETE ON slot_allowed_vehicle_type
    FOR EACH ROW EXECUTE FUNCTION fn_guard_slot_allowed_vehicle_type_delete();

-- -----------------------------------------------------------------------------
-- 8.13. Hàm trigger: fn_guard_prevent_plain_delete()
-- Chặn câu lệnh DELETE trực tiếp từ client trên các bảng cho phép dọn dẹp dữ liệu rác. Thực thi
-- bảo vệ 4 lớp: kiểm tra ngăn xếp PG_CONTEXT, kiểm tra namespace pg_proc
-- chống giả mạo, nonce giao dịch và điều kiện bản ghi đã xoá mềm.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_prevent_plain_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_context TEXT;
    v_line2 TEXT;
    v_line3 TEXT;
    v_active_nonce TEXT;
BEGIN
    -- 1. Kiểm tra ngăn xếp gọi qua PG_CONTEXT và xác minh không có fn_controlled_purge giả mạo ngoài schema public
    GET DIAGNOSTICS v_context = PG_CONTEXT;
    v_line2 := split_part(v_context, E'\n', 2);
    v_line3 := split_part(v_context, E'\n', 3);

    IF v_line2 !~ '^SQL statement "DELETE FROM [a-z_]+ WHERE .*"$'
       OR v_line3 !~ '^PL/pgSQL function (public\.)?fn_controlled_purge\([a-z ,]+\) line [0-9]+ at EXECUTE$'
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_proc p
           JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
           WHERE p.proname = 'fn_controlled_purge'
             AND n.nspname <> 'public'
       ) THEN
        RAISE EXCEPTION 'Thao tác xóa trực tiếp (plain DELETE) trên bảng % bị nghiêm cấm. Dữ liệu chỉ có thể được xóa mềm (soft-delete) hoặc xóa vĩnh viễn thông qua thủ tục controlled purge được ủy quyền.', TG_TABLE_NAME
            USING ERRCODE = '55000',
                  HINT = 'Use soft delete (UPDATE deleted_at) or invoke fn_controlled_purge() (TL-24).';
    END IF;

    -- 2. Kiểm tra token nonce mã hoá cục bộ trong giao dịch
    v_active_nonce := current_setting('app.purge_internal_nonce', true);
    IF v_active_nonce IS NULL OR btrim(v_active_nonce) = '' THEN
        RAISE EXCEPTION 'Xác thực thủ tục purge không hợp lệ: thiếu mã ủy quyền phiên làm việc (missing purge auth token).'
            USING ERRCODE = '42501';
    END IF;

    -- 3. Điều kiện rác bất khả xâm phạm: bản ghi đang hoạt động (deleted_at IS NULL) tuyệt đối không được phép dọn dẹp
    IF OLD.deleted_at IS NULL THEN
        RAISE EXCEPTION 'Bản ghi (ID: %) trên bảng % đang hoạt động (deleted_at IS NULL). Nghiêm cấm purge dữ liệu chưa xóa mềm.', OLD.id, TG_TABLE_NAME
            USING ERRCODE = '55000',
                  HINT = 'Only records currently in trash (deleted_at IS NOT NULL) can be purged (TL-24).';
    END IF;

    RETURN OLD;
END;
$$;

COMMENT ON FUNCTION fn_guard_prevent_plain_delete() IS 'Chặn lệnh DELETE trực tiếp trên các bảng dọn dẹp được, chỉ cho phép dọn dẹp qua public.fn_controlled_purge() kèm xác thực ngăn xếp gọi hàm, kiểm tra pg_proc và nonce giao dịch.';

CREATE TRIGGER trg_prevent_plain_delete_news
    BEFORE DELETE ON news
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_notification
    BEFORE DELETE ON notification
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_slot_reservation
    BEFORE DELETE ON slot_reservation
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_plate_blacklist
    BEFORE DELETE ON plate_blacklist
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_parking_slot
    BEFORE DELETE ON parking_slot
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_parking_zone
    BEFORE DELETE ON parking_zone
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_parking_floor
    BEFORE DELETE ON parking_floor
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_parking_lot
    BEFORE DELETE ON parking_lot
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_booking_policy
    BEFORE DELETE ON booking_policy
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_parking_gate
    BEFORE DELETE ON parking_gate
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_position
    BEFORE DELETE ON position
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_vehicle_type
    BEFORE DELETE ON vehicle_type
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_ticket_type
    BEFORE DELETE ON ticket_type
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_vehicle
    BEFORE DELETE ON vehicle
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_customer
    BEFORE DELETE ON customer
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_employee
    BEFORE DELETE ON employee
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

CREATE TRIGGER trg_prevent_plain_delete_account
    BEFORE DELETE ON account
    FOR EACH ROW EXECUTE FUNCTION fn_guard_prevent_plain_delete();

-- -----------------------------------------------------------------------------
-- 8.14. Hàm: fn_controlled_purge()
-- Hàm dọn dẹp an toàn có kiểm soát cho các bản ghi rác vượt quá thời hạn lưu trữ.
-- SECURITY DEFINER với search_path cố định, bảo vệ ngăn xếp gọi hàm không thể vượt qua,
-- kiểm tra ẩn danh khách hàng theo Nghị định 13/2023/NĐ-CP và ghi nhật ký kiểm toán vào activity_log.
-- Mô hình phân quyền tối thiểu:
--   - PUBLIC: REVOKE ALL ON FUNCTION fn_controlled_purge FROM PUBLIC.
--   - app_rw (vai trò ứng dụng thông thường): không có quyền EXECUTE trên fn_controlled_purge.
--   - db_admin / purge_operator (vai trò bảo trì): được cấp quyền EXECUTE để dọn dẹp dữ liệu rác định kỳ.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_controlled_purge(
    p_table_name VARCHAR DEFAULT NULL,
    p_retention INTERVAL DEFAULT INTERVAL '30 days',
    p_dry_run BOOLEAN DEFAULT TRUE,
    p_purged_by BIGINT DEFAULT NULL,
    p_target_id BIGINT DEFAULT NULL
)
RETURNS TABLE (
    table_name VARCHAR,
    eligible_count BIGINT,
    purged_count BIGINT,
    status VARCHAR,
    details TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_allowed_tables VARCHAR[] := ARRAY[
        'news', 'notification', 'slot_reservation', 'plate_blacklist', 'booking_policy',
        'parking_slot', 'parking_zone', 'parking_floor', 'parking_lot', 'parking_gate',
        'vehicle', 'customer', 'employee', 'account',
        'ticket_type', 'vehicle_type', 'position'
    ];
    v_forbidden_tables VARCHAR[] := ARRAY[
        'ticket', 'ticket_renewal', 'payment', 'vehicle_entry_exit_log', 'activity_log', 'system_alert',
        'administrative_province', 'administrative_district', 'administrative_ward'
    ];
    v_tbl VARCHAR;
    v_eligible BIGINT;
    v_purged BIGINT;
    v_skipped BIGINT;
    v_row_id BIGINT;
    v_cutoff TIMESTAMPTZ;
    v_target_exists BOOLEAN;
    v_target_deleted_at TIMESTAMPTZ;
    v_target_anonymized BOOLEAN;
    v_nonce TEXT;
    v_sql TEXT;
BEGIN
    -- Kiểm tra tính hợp lệ của tham số lưu trữ (sàn tối thiểu 30 ngày)
    IF p_retention IS NULL OR p_retention < INTERVAL '30 days' THEN
        RAISE EXCEPTION 'Khoảng thời gian lưu trữ tối thiểu (p_retention) không hợp lệ (yêu cầu tối thiểu 30 ngày).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_target_id IS NOT NULL AND p_table_name IS NULL THEN
        RAISE EXCEPTION 'Phải chỉ định tên bảng (p_table_name) khi purge theo ID cụ thể (p_target_id).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_cutoff := CURRENT_TIMESTAMP - p_retention;

    -- Kiểm tra bảng đích có thuộc danh sách bị cấm hoặc không hợp lệ
    IF p_table_name IS NOT NULL THEN
        IF lower(btrim(p_table_name)) = ANY(v_forbidden_tables) THEN
            RAISE EXCEPTION 'Bảng % nằm trong danh mục bất biến/không thể xóa, nghiêm cấm purge.', p_table_name
                USING ERRCODE = '55000';
        END IF;
        IF NOT (lower(btrim(p_table_name)) = ANY(v_allowed_tables)) THEN
            RAISE EXCEPTION 'Bảng % không nằm trong danh mục bảng được phép purge.', p_table_name
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END IF;

    -- Lặp qua các bảng đích được phép dọn dẹp
    FOREACH v_tbl IN ARRAY CASE
        WHEN p_table_name IS NOT NULL THEN ARRAY[lower(btrim(p_table_name))]
        ELSE v_allowed_tables
    END
    LOOP
        -- Khi dọn dẹp theo ID bản ghi cụ thể, kiểm tra rõ ràng bản ghi tồn tại, đã xoá mềm,
        -- thoả mãn thời hạn lưu trữ, và (đối với customer) đã được ẩn danh theo Nghị định 13/2023/NĐ-CP.
        IF p_target_id IS NOT NULL THEN
            v_target_exists := FALSE;
            IF v_tbl = 'customer' THEN
                v_sql := format('SELECT TRUE, deleted_at, is_anonymized FROM %I WHERE id = $1', v_tbl);
                EXECUTE v_sql INTO v_target_exists, v_target_deleted_at, v_target_anonymized USING p_target_id;
            ELSE
                v_sql := format('SELECT TRUE, deleted_at, TRUE FROM %I WHERE id = $1', v_tbl);
                EXECUTE v_sql INTO v_target_exists, v_target_deleted_at, v_target_anonymized USING p_target_id;
            END IF;

            IF NOT COALESCE(v_target_exists, FALSE) THEN
                RAISE EXCEPTION 'Bản ghi cần purge (ID: %) không tồn tại trên bảng %.', p_target_id, v_tbl
                    USING ERRCODE = 'no_data_found';
            END IF;

            IF v_target_deleted_at IS NULL THEN
                RAISE EXCEPTION 'Bản ghi (ID: %) trên bảng % đang hoạt động (deleted_at IS NULL). Nghiêm cấm purge dữ liệu chưa xóa mềm.', p_target_id, v_tbl
                    USING ERRCODE = '55000',
                          HINT = 'Only records currently in trash (deleted_at IS NOT NULL) can be purged (TL-24).';
            END IF;

            IF v_target_deleted_at >= v_cutoff THEN
                RAISE EXCEPTION 'Bản ghi (ID: %) trên bảng % chưa đủ thời gian lưu giữ trong thùng rác (retention: %).', p_target_id, v_tbl, p_retention
                    USING ERRCODE = '55000';
            END IF;

            IF v_tbl = 'customer' AND NOT COALESCE(v_target_anonymized, FALSE) THEN
                RAISE EXCEPTION 'Khách hàng (ID: %) chưa được ẩn danh hóa dữ liệu cá nhân theo Nghị định 13/2023/NĐ-CP, không được phép purge.', p_target_id
                    USING ERRCODE = '55000';
            END IF;

            v_eligible := 1;
        ELSE
            -- Đếm số bản ghi rác đủ điều kiện trong chế độ chạy theo lô
            IF v_tbl = 'customer' THEN
                v_sql := format(
                    'SELECT count(*) FROM %I WHERE deleted_at IS NOT NULL AND deleted_at < $1 AND is_anonymized = TRUE',
                    v_tbl
                );
            ELSE
                v_sql := format(
                    'SELECT count(*) FROM %I WHERE deleted_at IS NOT NULL AND deleted_at < $1',
                    v_tbl
                );
            END IF;
            EXECUTE v_sql INTO v_eligible USING v_cutoff;
        END IF;

        IF p_dry_run THEN
            table_name := v_tbl;
            eligible_count := v_eligible;
            purged_count := 0;
            status := 'DRY_RUN';
            details := format('Simulated purge: %s rows eligible in trash older than %s.', v_eligible, p_retention);
            RETURN NEXT;
        ELSE
            IF v_eligible > 0 THEN
                -- Thiết lập token nonce nội bộ cho giao dịch này
                v_nonce := gen_random_uuid()::text;
                PERFORM set_config('app.purge_internal_nonce', v_nonce, true);

                v_purged := 0;
                v_skipped := 0;

                -- Thực hiện thao tác dọn dẹp thực tế
                IF p_target_id IS NOT NULL THEN
                    -- Chế độ đơn bản ghi: báo lỗi rõ ràng nếu còn khoá ngoại tham chiếu (không bỏ qua lỗi)
                    -- Nếu là account, xoá các token liên quan trong cùng giao dịch
                    IF v_tbl = 'account' THEN
                        DELETE FROM persistent_login_token WHERE account_id = p_target_id;
                        DELETE FROM password_reset_token WHERE account_id = p_target_id;
                    END IF;

                    IF v_tbl = 'customer' THEN
                        v_sql := format('DELETE FROM %I WHERE id = $2 AND deleted_at IS NOT NULL AND deleted_at < $1 AND is_anonymized = TRUE', v_tbl);
                    ELSE
                        v_sql := format('DELETE FROM %I WHERE id = $2 AND deleted_at IS NOT NULL AND deleted_at < $1', v_tbl);
                    END IF;

                    BEGIN
                        EXECUTE v_sql USING v_cutoff, p_target_id;
                        GET DIAGNOSTICS v_purged = ROW_COUNT;
                    EXCEPTION WHEN foreign_key_violation OR restrict_violation THEN
                        RAISE EXCEPTION 'Bản ghi (ID: %) trên bảng % đang được tham chiếu bởi dữ liệu khác, không thể purge.', p_target_id, v_tbl
                            USING ERRCODE = 'foreign_key_violation';
                    END;
                ELSE
                    -- Chế độ theo lô: lặp qua các bản ghi rác đủ điều kiện, bỏ qua các dòng đang có tham chiếu
                    IF v_tbl = 'customer' THEN
                        v_sql := format('SELECT id FROM %I WHERE deleted_at IS NOT NULL AND deleted_at < $1 AND is_anonymized = TRUE', v_tbl);
                    ELSE
                        v_sql := format('SELECT id FROM %I WHERE deleted_at IS NOT NULL AND deleted_at < $1', v_tbl);
                    END IF;

                    FOR v_row_id IN EXECUTE v_sql USING v_cutoff
                    LOOP
                        BEGIN
                            -- Nếu là account, xoá các token liên quan trước trong cùng giao dịch con
                            IF v_tbl = 'account' THEN
                                DELETE FROM persistent_login_token WHERE account_id = v_row_id;
                                DELETE FROM password_reset_token WHERE account_id = v_row_id;
                            END IF;

                            EXECUTE format('DELETE FROM %I WHERE id = $1', v_tbl) USING v_row_id;
                            v_purged := v_purged + 1;
                        EXCEPTION WHEN foreign_key_violation OR restrict_violation THEN
                            v_skipped := v_skipped + 1;
                        END;
                    END LOOP;
                END IF;

                -- Xoá bỏ nonce
                PERFORM set_config('app.purge_internal_nonce', '', true);

                -- Ghi nhật ký kiểm toán khớp với lược đồ (actor_account_id, action, entity_type, entity_id, message)
                IF v_purged > 0 THEN
                    INSERT INTO activity_log (actor_account_id, action, entity_type, entity_id, message)
                    VALUES (
                        p_purged_by,
                        'PURGE',
                        v_tbl,
                        p_target_id,
                        format('Controlled purge: Đã xóa %s bản ghi từ %s (retention: %s).', v_purged, v_tbl, p_retention)
                    );
                END IF;

                table_name := v_tbl;
                eligible_count := v_eligible;
                purged_count := v_purged;
                IF v_purged = v_eligible THEN
                    status := 'PURGED';
                ELSIF v_purged > 0 THEN
                    status := 'PARTIALLY_PURGED';
                ELSE
                    status := 'SKIPPED';
                END IF;

                IF v_skipped > 0 THEN
                    details := format('Successfully purged %s rows, skipped %s rows referenced by foreign keys.', v_purged, v_skipped);
                ELSE
                    details := format('Successfully purged %s rows.', v_purged);
                END IF;
                RETURN NEXT;
            ELSE
                table_name := v_tbl;
                eligible_count := 0;
                purged_count := 0;
                status := 'SKIPPED';
                details := 'No eligible trash records to purge.';
                RETURN NEXT;
            END IF;
        END IF;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION fn_controlled_purge(VARCHAR, INTERVAL, BOOLEAN, BIGINT, BIGINT) IS 'Hàm dọn dẹp an toàn có kiểm soát cho các bản ghi rác cũ hơn thời hạn lưu trữ (sàn tối thiểu >= 30 ngày, bỏ qua ràng buộc FK từng dòng ở chế độ lô và dọn dẹp token xác thực cho account).';

REVOKE ALL ON FUNCTION fn_controlled_purge(VARCHAR, INTERVAL, BOOLEAN, BIGINT, BIGINT) FROM PUBLIC;

-- -----------------------------------------------------------------------------
-- 8.15. Hàm trigger: fn_guard_soft_delete_and_restore()
-- Thực thi các quy tắc nghiệp vụ khi xoá mềm và
-- khôi phục (đặt lại deleted_by và kiểm tra tính hợp lệ của phân cấp cha còn hoạt động).
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_soft_delete_and_restore()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_count BIGINT;
    v_parent_deleted TIMESTAMPTZ;
BEGIN
    -- =========================================================================
    -- NHÁNH A: THAO TÁC XOÁ MỀM (OLD.deleted_at IS NULL VÀ NEW.deleted_at IS NOT NULL)
    -- =========================================================================
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        -- 1. Kiểm soát xoá mềm parking_slot
        IF TG_TABLE_NAME = 'parking_slot' THEN
            IF OLD.status IN ('OCCUPIED', 'CHARGING') THEN
                RAISE EXCEPTION 'Không thể xóa vị trí đỗ xe đang có phương tiện đỗ (trạng thái OCCUPIED).'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Cannot soft delete an occupied or charging slot (PROP-DEL-05-OCCUPIED, SRS 4.8.5, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM vehicle_entry_exit_log
            WHERE slot_id = OLD.id AND exit_time IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Không thể xóa vị trí đỗ xe đang có phương tiện đỗ (trạng thái OCCUPIED).'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Cannot soft delete a slot with an open parking session (PROP-DEL-05-OCCUPIED, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM ticket
            WHERE slot_id = OLD.id
              AND deleted_at IS NULL
              AND status IN ('ACTIVE', 'RENEWING')
              AND effective_to > CURRENT_TIMESTAMP;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Vị trí đỗ xe đang có phương tiện đăng ký vé, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-4.8.5-P02 (SRS 4.8.5 TH1, MSG-4.5.2-M02, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM slot_reservation
            WHERE slot_id = OLD.id
              AND deleted_at IS NULL
              AND status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN')
              AND reserved_until > CURRENT_TIMESTAMP;
            IF v_count > 0 OR OLD.status = 'RESERVED' THEN
                RAISE EXCEPTION 'Vị trí đỗ xe đang được đặt trước còn hiệu lực, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Cannot soft delete a slot with an active advance reservation (PROP-DEL-05-RESERVED, DEL-05, TL-25).';
            END IF;

        -- 2. Kiểm soát xoá mềm customer
        ELSIF TG_TABLE_NAME = 'customer' THEN
            SELECT count(*) INTO v_count
            FROM vehicle_entry_exit_log l
            JOIN vehicle v ON v.id = l.vehicle_id
            WHERE v.customer_id = OLD.id AND l.exit_time IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Khách hàng đang có phương tiện trong bãi, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-4.4.5-P02 (DEL-02, OQ-15, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM ticket
            WHERE customer_id = OLD.id
              AND deleted_at IS NULL
              AND status IN ('ACTIVE', 'RENEWING')
              AND effective_to > CURRENT_TIMESTAMP;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Khách hàng đang có vé xe còn hiệu lực, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-4.4.5-P03 (DEL-02, OQ-15, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM vehicle
            WHERE customer_id = OLD.id AND deleted_at IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Khách hàng đang có phương tiện hoạt động trong hệ thống, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Customer still has active registered vehicles (PROP-DEL-02-ACTIVE-VEH, DEL-02, TL-25).';
            END IF;

        -- 3. Kiểm soát xoá mềm vehicle
        ELSIF TG_TABLE_NAME = 'vehicle' THEN
            SELECT count(*) INTO v_count
            FROM vehicle_entry_exit_log
            WHERE vehicle_id = OLD.id AND exit_time IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Phương tiện đang đỗ trong bãi xe (có phiên đỗ đang mở), không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Vehicle has uncompleted parking session (PROP-DEL-03-OPEN-SES, DEL-03, OQ-41, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM ticket
            WHERE vehicle_id = OLD.id
              AND deleted_at IS NULL
              AND status IN ('ACTIVE', 'RENEWING')
              AND effective_to > CURRENT_TIMESTAMP;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Phương tiện đang có vé đỗ xe còn hiệu lực, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Vehicle holds active ticket (PROP-DEL-03-ACTIVE-TKT, DEL-03, OQ-41, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM slot_reservation
            WHERE vehicle_id = OLD.id
              AND deleted_at IS NULL
              AND status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN')
              AND reserved_until > CURRENT_TIMESTAMP;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Phương tiện đang có đặt trước vị trí đỗ xe còn hiệu lực, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Vehicle holds active slot reservation (PROP-DEL-03-ACTIVE-RSV, DEL-03, TL-25).';
            END IF;

        -- 4. Kiểm soát xoá mềm account
        ELSIF TG_TABLE_NAME = 'account' THEN
            IF NEW.deleted_by IS NOT NULL AND NEW.deleted_by = OLD.id THEN
                RAISE EXCEPTION 'Tài khoản đang đăng nhập không được phép tự xóa chính mình.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Self-deletion of the authenticated account is prohibited (PROP-DEL-01-SELF, DEL-01, OQ-10).';
            END IF;

            IF OLD.role = 'MANAGER' AND OLD.is_active = TRUE THEN
                SELECT count(*) INTO v_count
                FROM account
                WHERE role = 'MANAGER'
                  AND is_active = TRUE
                  AND deleted_at IS NULL
                  AND id <> OLD.id;
                IF v_count = 0 THEN
                    RAISE EXCEPTION 'Không thể xóa tài khoản Quản lý hoạt động cuối cùng trong hệ thống.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Last active manager safeguard (PROP-DEL-01-LAST-MGR, DEL-01, OQ-10, TL-25).';
                END IF;
            END IF;

        -- 5. Kiểm soát xoá mềm employee
        ELSIF TG_TABLE_NAME = 'employee' THEN
            IF NEW.deleted_by IS NOT NULL AND OLD.account_id IS NOT NULL AND NEW.deleted_by = OLD.account_id THEN
                RAISE EXCEPTION 'Nhân viên đang đăng nhập không được phép tự xóa hồ sơ của chính mình.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Self-deletion of the authenticated employee is prohibited (PROP-DEL-01-SELF-EMP, DEL-01, OQ-10).';
            END IF;

            IF OLD.account_id IS NOT NULL THEN
                SELECT count(*) INTO v_count
                FROM account a
                WHERE a.id = OLD.account_id
                  AND a.role = 'MANAGER'
                  AND a.is_active = TRUE
                  AND a.deleted_at IS NULL;
                IF v_count > 0 THEN
                    SELECT count(*) INTO v_count
                    FROM account
                    WHERE role = 'MANAGER'
                      AND is_active = TRUE
                      AND deleted_at IS NULL
                      AND id <> OLD.account_id;
                    IF v_count = 0 THEN
                        RAISE EXCEPTION 'Không thể xóa nhân viên gắn với tài khoản Quản lý hoạt động cuối cùng.'
                            USING ERRCODE = 'check_violation',
                                  HINT = 'Last active manager safeguard (PROP-DEL-01-LAST-MGR-EMP, DEL-01, OQ-10, TL-25).';
                    END IF;
                END IF;
            END IF;

        -- 6. Kiểm soát xoá mềm phân cấp parking_lot, parking_floor, parking_zone
        ELSIF TG_TABLE_NAME = 'parking_lot' THEN
            SELECT count(*) INTO v_count
            FROM parking_floor
            WHERE lot_id = OLD.id AND deleted_at IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Bãi đỗ xe còn tầng đang hoạt động, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Active child parking floors exist (PROP-DEL-06-LOT, DEL-06, TL-25).';
            END IF;

        ELSIF TG_TABLE_NAME = 'parking_floor' THEN
            SELECT count(*) INTO v_count
            FROM parking_zone
            WHERE floor_id = OLD.id AND deleted_at IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Tầng bãi xe còn khu vực (zone) đang hoạt động, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Active child parking zones exist (PROP-DEL-06-FLOOR, DEL-06, TL-25).';
            END IF;

        ELSIF TG_TABLE_NAME = 'parking_zone' THEN
            SELECT count(*) INTO v_count
            FROM parking_slot
            WHERE zone_id = OLD.id AND deleted_at IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Khu vực đỗ xe còn vị trí (slot) đang hoạt động, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Active child parking slots exist (PROP-DEL-06-ZONE, DEL-06, TL-25).';
            END IF;

        -- 7. Kiểm soát xoá mềm ticket_type
        ELSIF TG_TABLE_NAME = 'ticket_type' THEN
            SELECT count(*) INTO v_count
            FROM ticket
            WHERE ticket_type_id = OLD.id
              AND deleted_at IS NULL
              AND status IN ('ACTIVE', 'RENEWING')
              AND effective_to > CURRENT_TIMESTAMP;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Loại vé đang được sử dụng bởi các vé còn hiệu lực, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Active tickets bound to this ticket_type (PROP-DEL-06-TICKET-TYPE, DEL-06, TL-25).';
            END IF;

        -- 8. Kiểm soát xoá mềm position
        ELSIF TG_TABLE_NAME = 'position' THEN
            SELECT count(*) INTO v_count
            FROM employee
            WHERE position_id = OLD.id AND deleted_at IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Chức vụ đang được phân công cho nhân viên đang hoạt động, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Active employees assigned to this position (PROP-DEL-06-POSITION, DEL-06, TL-25).';
            END IF;

        -- 9. Kiểm soát xoá mềm vehicle_type
        ELSIF TG_TABLE_NAME = 'vehicle_type' THEN
            SELECT count(*) INTO v_count
            FROM vehicle
            WHERE vehicle_type_id = OLD.id AND deleted_at IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Loại xe đang được liên kết với phương tiện đang hoạt động, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Active vehicles using this vehicle_type (PROP-DEL-06-VEHICLE-TYPE, DEL-06, TL-25).';
            END IF;

        -- 10. Kiểm soát xoá mềm parking_gate
        ELSIF TG_TABLE_NAME = 'parking_gate' THEN
            SELECT count(*) INTO v_count
            FROM vehicle_entry_exit_log
            WHERE (entry_gate_id = OLD.id OR exit_gate_id = OLD.id)
              AND exit_time IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Cổng kiểm soát đang xử lý phiên đỗ xe chưa hoàn thành, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Gate has active open sessions (PROP-DEL-06-GATE, DEL-06, TL-25).';
            END IF;

        -- 11. Kiểm soát xoá mềm ticket
        ELSIF TG_TABLE_NAME = 'ticket' THEN
            IF OLD.effective_to > CURRENT_TIMESTAMP AND OLD.status IN ('ACTIVE', 'RENEWING') THEN
                RAISE EXCEPTION 'Vé chưa hết hạn, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-4.6.4-P01 (SRS 4.6.4 TH1, DEL-04, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM ticket_renewal
            WHERE ticket_id = OLD.id;
            IF OLD.status = 'RENEWED' OR v_count > 0 THEN
                RAISE EXCEPTION 'Vé đã được gia hạn, không được phép xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-4.6.4-P02 (SRS 4.6.4 TH1, OQ-18, DEL-04, TL-25).';
            END IF;

            SELECT count(*) INTO v_count
            FROM vehicle_entry_exit_log
            WHERE (ticket_id = OLD.id OR vehicle_id = OLD.vehicle_id)
              AND exit_time IS NULL;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Phương tiện liên kết với vé đang đỗ trong bãi xe, không được phép xóa vé.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Vehicle is inside lot (PROP-DEL-04-OPEN-SES, DEL-04, OQ-42, TL-25).';
            END IF;

        -- 12. Kiểm soát xoá mềm payment
        ELSIF TG_TABLE_NAME = 'payment' THEN
            IF OLD.status IN ('PAID', 'REFUNDED') THEN
                RAISE EXCEPTION 'Không thể xóa chứng từ thanh toán đã hoàn thành hoặc đã hoàn tiền (trạng thái PAID/REFUNDED).'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Cannot soft delete payment with status PAID or REFUNDED (PROP-DEL-PAYMENT-SETTLED, TL-39).';
            END IF;

        -- 13. Kiểm soát xoá mềm slot_reservation
        ELSIF TG_TABLE_NAME = 'slot_reservation' THEN
            IF OLD.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN') THEN
                RAISE EXCEPTION 'Không thể xóa đặt chỗ đang có hiệu lực (trạng thái %). Vui lòng hủy đặt chỗ trước khi xóa.', OLD.status
                    USING ERRCODE = 'check_violation',
                          HINT = 'Cannot soft delete active slot reservation (PROP-DEL-RESERVATION-ACTIVE).';
            END IF;
        END IF;

        RETURN NEW;

    -- =========================================================================
    -- NHÁNH B: THAO TÁC KHÔI PHỤC (OLD.deleted_at IS NOT NULL VÀ NEW.deleted_at IS NULL)
    -- =========================================================================
    ELSIF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL THEN
        -- Khôi phục bản ghi sẽ xoá sạch cả deleted_at và deleted_by
        NEW.deleted_by := NULL;

        -- 1. Khôi phục vehicle: customer cha, vehicle_type và ticket_type (nếu có) phải còn hoạt động
        IF TG_TABLE_NAME = 'vehicle' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM customer WHERE id = NEW.customer_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục phương tiện khi khách hàng sở hữu đang bị xóa hoặc không hoạt động.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Parent customer is deleted (TL-26).';
            END IF;

            SELECT deleted_at INTO v_parent_deleted
            FROM vehicle_type WHERE id = NEW.vehicle_type_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục phương tiện khi loại xe liên kết đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Parent vehicle_type is deleted (TL-26).';
            END IF;

            IF NEW.ticket_type_id IS NOT NULL THEN
                SELECT deleted_at INTO v_parent_deleted
                FROM ticket_type WHERE id = NEW.ticket_type_id;
                IF v_parent_deleted IS NOT NULL THEN
                    RAISE EXCEPTION 'Không thể khôi phục phương tiện khi loại vé liên kết đang bị xóa.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Parent ticket_type is deleted (TL-26).';
                END IF;
            END IF;

        -- 2. Khôi phục parking_slot: zone cha phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'parking_slot' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM parking_zone WHERE id = NEW.zone_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục vị trí đỗ khi khu vực đỗ (zone) đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Parent zone is deleted (TL-26).';
            END IF;

        -- 3. Khôi phục parking_zone: floor cha phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'parking_zone' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM parking_floor WHERE id = NEW.floor_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục khu vực đỗ khi tầng đỗ (floor) đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Parent floor is deleted (TL-26).';
            END IF;

        -- 4. Khôi phục parking_floor: lot cha phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'parking_floor' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM parking_lot WHERE id = NEW.lot_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục tầng đỗ khi bãi xe (lot) đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Parent lot is deleted (TL-26).';
            END IF;

        -- 5. Khôi phục parking_gate: lot cha phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'parking_gate' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM parking_lot WHERE id = NEW.lot_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục cổng kiểm soát khi bãi xe (lot) đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Parent lot is deleted (TL-26).';
            END IF;

        -- 6. Khôi phục employee: position và account (nếu có) phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'employee' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM position WHERE id = NEW.position_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục nhân viên khi chức vụ tương ứng đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Assigned position is deleted (TL-26).';
            END IF;

            IF NEW.account_id IS NOT NULL THEN
                SELECT deleted_at INTO v_parent_deleted
                FROM account WHERE id = NEW.account_id;
                IF v_parent_deleted IS NOT NULL THEN
                    RAISE EXCEPTION 'Không thể khôi phục nhân viên khi tài khoản đăng nhập liên kết đang bị xóa.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Linked account is deleted (TL-26).';
                END IF;
            END IF;

        -- 7. Khôi phục customer: account (nếu có) phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'customer' THEN
            IF NEW.account_id IS NOT NULL THEN
                SELECT deleted_at INTO v_parent_deleted
                FROM account WHERE id = NEW.account_id;
                IF v_parent_deleted IS NOT NULL THEN
                    RAISE EXCEPTION 'Không thể khôi phục khách hàng khi tài khoản đăng nhập liên kết đang bị xóa.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Linked account is deleted (TL-26).';
                END IF;
            END IF;

        -- 8. Khôi phục slot_reservation: slot, customer (nếu có) và vehicle (nếu có) phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'slot_reservation' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM parking_slot WHERE id = NEW.slot_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục đặt chỗ khi vị trí đỗ (slot) đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Reserved slot is deleted (TL-26).';
            END IF;

            IF NEW.customer_id IS NOT NULL THEN
                SELECT deleted_at INTO v_parent_deleted
                FROM customer WHERE id = NEW.customer_id;
                IF v_parent_deleted IS NOT NULL THEN
                    RAISE EXCEPTION 'Không thể khôi phục đặt chỗ khi khách hàng liên kết đang bị xóa.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Linked customer is deleted (TL-26).';
                END IF;
            END IF;

            IF NEW.vehicle_id IS NOT NULL THEN
                SELECT deleted_at INTO v_parent_deleted
                FROM vehicle WHERE id = NEW.vehicle_id;
                IF v_parent_deleted IS NOT NULL THEN
                    RAISE EXCEPTION 'Không thể khôi phục đặt chỗ khi phương tiện liên kết đang bị xóa.'
                        USING ERRCODE = 'check_violation',
                              HINT = 'Linked vehicle is deleted (TL-26).';
                END IF;
            END IF;

        -- 9. Khôi phục ticket: customer, vehicle, slot và ticket_type phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'ticket' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM customer WHERE id = NEW.customer_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục vé khi khách hàng liên kết đang bị xóa.'
                    USING ERRCODE = 'check_violation';
            END IF;

            SELECT deleted_at INTO v_parent_deleted
            FROM vehicle WHERE id = NEW.vehicle_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục vé khi phương tiện liên kết đang bị xóa.'
                    USING ERRCODE = 'check_violation';
            END IF;

            SELECT deleted_at INTO v_parent_deleted
            FROM parking_slot WHERE id = NEW.slot_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục vé khi vị trí đỗ liên kết đang bị xóa.'
                    USING ERRCODE = 'check_violation';
            END IF;

            SELECT deleted_at INTO v_parent_deleted
            FROM ticket_type WHERE id = NEW.ticket_type_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục vé khi loại vé liên kết đang bị xóa.'
                    USING ERRCODE = 'check_violation';
            END IF;

        -- 10. Khôi phục payment: ticket (nếu có) và nhân viên received_by phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'payment' THEN
            IF NEW.ticket_id IS NOT NULL THEN
                SELECT deleted_at INTO v_parent_deleted
                FROM ticket WHERE id = NEW.ticket_id;
                IF v_parent_deleted IS NOT NULL THEN
                    RAISE EXCEPTION 'Không thể khôi phục thanh toán khi vé liên kết đang bị xóa.'
                        USING ERRCODE = 'check_violation';
                END IF;
            END IF;

        -- 11. Khôi phục news: nhân viên tác giả phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'news' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM employee WHERE id = NEW.author_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục bài viết khi nhân viên tác giả đang bị xóa.'
                    USING ERRCODE = 'check_violation';
            END IF;

        -- 12. Khôi phục notification: tài khoản người nhận (nếu có) phải còn hoạt động
        ELSIF TG_TABLE_NAME = 'notification' THEN
            IF NEW.recipient_account_id IS NOT NULL THEN
                SELECT deleted_at INTO v_parent_deleted
                FROM account WHERE id = NEW.recipient_account_id;
                IF v_parent_deleted IS NOT NULL THEN
                    RAISE EXCEPTION 'Không thể khôi phục thông báo khi tài khoản người nhận đang bị xóa.'
                        USING ERRCODE = 'check_violation';
                END IF;
            END IF;

        -- 13. Khôi phục booking_policy: lot cha phải còn hoạt động và chưa có chính sách hoạt động nào cho lot_id
        ELSIF TG_TABLE_NAME = 'booking_policy' THEN
            SELECT deleted_at INTO v_parent_deleted
            FROM parking_lot WHERE id = NEW.lot_id;
            IF v_parent_deleted IS NOT NULL THEN
                RAISE EXCEPTION 'Không thể khôi phục chính sách đặt chỗ khi bãi xe (lot) đang bị xóa.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Parent lot is deleted (TL-26).';
            END IF;

            SELECT count(*) INTO v_count
            FROM booking_policy
            WHERE lot_id = NEW.lot_id AND deleted_at IS NULL AND id <> NEW.id;
            IF v_count > 0 THEN
                RAISE EXCEPTION 'Bãi đỗ xe đã có chính sách đặt chỗ đang hoạt động, không thể khôi phục thêm.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'Active booking policy already exists for this lot (PROP-RESTORE-BOOKING-POLICY).';
            END IF;
        END IF;

        RETURN NEW;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_guard_soft_delete_and_restore() IS 'Kiểm soát các thao tác xoá mềm và khôi phục trên toàn bộ 18 bảng xoá mềm, bảo đảm tính toàn vẹn phân cấp cha, bảo vệ thanh toán đã hoàn tất và tự động xoá deleted_by.';

CREATE TRIGGER trg_guard_soft_delete_and_restore_account
    BEFORE UPDATE OF deleted_at ON account
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_position
    BEFORE UPDATE OF deleted_at ON position
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_employee
    BEFORE UPDATE OF deleted_at ON employee
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_customer
    BEFORE UPDATE OF deleted_at ON customer
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_plate_blacklist
    BEFORE UPDATE OF deleted_at ON plate_blacklist
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_vehicle_type
    BEFORE UPDATE OF deleted_at ON vehicle_type
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_ticket_type
    BEFORE UPDATE OF deleted_at ON ticket_type
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_vehicle
    BEFORE UPDATE OF deleted_at ON vehicle
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_parking_lot
    BEFORE UPDATE OF deleted_at ON parking_lot
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_booking_policy
    BEFORE UPDATE OF deleted_at ON booking_policy
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_parking_floor
    BEFORE UPDATE OF deleted_at ON parking_floor
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_parking_zone
    BEFORE UPDATE OF deleted_at ON parking_zone
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_parking_slot
    BEFORE UPDATE OF deleted_at ON parking_slot
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_slot_reservation
    BEFORE UPDATE OF deleted_at ON slot_reservation
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_ticket
    BEFORE UPDATE OF deleted_at ON ticket
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_parking_gate
    BEFORE UPDATE OF deleted_at ON parking_gate
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_payment
    BEFORE UPDATE OF deleted_at ON payment
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_news
    BEFORE UPDATE OF deleted_at ON news
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

CREATE TRIGGER trg_guard_soft_delete_and_restore_notification
    BEFORE UPDATE OF deleted_at ON notification
    FOR EACH ROW EXECUTE FUNCTION fn_guard_soft_delete_and_restore();

-- -----------------------------------------------------------------------------
-- 8.16. Hàm trigger: fn_audit_soft_delete_and_restore()
-- Tự động ghi nhận bản ghi kiểm toán thao tác SOFT_DELETE và RESTORE vào
-- activity_log theo quy tắc chỉ ghi thêm.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_audit_soft_delete_and_restore()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        INSERT INTO activity_log (actor_account_id, action, entity_type, entity_id, message)
        VALUES (
            NEW.deleted_by,
            'SOFT_DELETE',
            TG_TABLE_NAME,
            OLD.id,
            format('Xóa mềm %s (ID: %s) bởi tài khoản %s.', TG_TABLE_NAME, OLD.id, COALESCE(NEW.deleted_by::text, 'UNKNOWN'))
        );
    ELSIF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL THEN
        INSERT INTO activity_log (actor_account_id, action, entity_type, entity_id, message)
        VALUES (
            NULL,
            'RESTORE',
            TG_TABLE_NAME,
            OLD.id,
            format('Khôi phục %s (ID: %s) từ thùng rác.', TG_TABLE_NAME, OLD.id)
        );
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_audit_soft_delete_and_restore() IS 'Ghi nhật ký chuyển đổi vòng đời SOFT_DELETE và RESTORE vào activity_log.';

CREATE TRIGGER trg_audit_soft_delete_and_restore_account
    AFTER UPDATE OF deleted_at ON account
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_position
    AFTER UPDATE OF deleted_at ON position
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_employee
    AFTER UPDATE OF deleted_at ON employee
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_customer
    AFTER UPDATE OF deleted_at ON customer
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_plate_blacklist
    AFTER UPDATE OF deleted_at ON plate_blacklist
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_vehicle_type
    AFTER UPDATE OF deleted_at ON vehicle_type
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_ticket_type
    AFTER UPDATE OF deleted_at ON ticket_type
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_vehicle
    AFTER UPDATE OF deleted_at ON vehicle
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_parking_lot
    AFTER UPDATE OF deleted_at ON parking_lot
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_booking_policy
    AFTER UPDATE OF deleted_at ON booking_policy
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_parking_floor
    AFTER UPDATE OF deleted_at ON parking_floor
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_parking_zone
    AFTER UPDATE OF deleted_at ON parking_zone
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_parking_slot
    AFTER UPDATE OF deleted_at ON parking_slot
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_slot_reservation
    AFTER UPDATE OF deleted_at ON slot_reservation
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_ticket
    AFTER UPDATE OF deleted_at ON ticket
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_parking_gate
    AFTER UPDATE OF deleted_at ON parking_gate
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_payment
    AFTER UPDATE OF deleted_at ON payment
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_news
    AFTER UPDATE OF deleted_at ON news
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

CREATE TRIGGER trg_audit_soft_delete_and_restore_notification
    AFTER UPDATE OF deleted_at ON notification
    FOR EACH ROW EXECUTE FUNCTION fn_audit_soft_delete_and_restore();

-- -----------------------------------------------------------------------------
-- 8.17. Hàm trigger: fn_guard_payment_update()
-- Thực thi chuyển đổi trạng thái thanh toán và tính bất biến của thanh toán đã tất toán:
--   - Quy tắc xoá mềm:
--       * Nghiêm cấm sửa đổi hoặc chuyển trạng thái thanh toán đang trong thùng rác (deleted_at IS NOT NULL)
--         khi chưa khôi phục.
--       * Thanh toán đã tất toán (PAID, REFUNDED) tuyệt đối không được phép xoá mềm (PROP-DEL-PAYMENT-SETTLED).
--   - Quy tắc chuyển đổi trạng thái:
--       * UNPAID -> PAID hoặc CANCELLED
--       * PAID -> chỉ chuyển sang REFUNDED
--       * REFUNDED và CANCELLED là các trạng thái kết thúc
--       * Không cho phép chuyển ngược về UNPAID
--       * Chuyển đổi không hợp lệ sẽ báo lỗi check_violation kèm mã PROP-PAY-STATUS-TRANSITION.
--   - Tính bất biến của thanh toán đã tất toán (OLD.status IN ('PAID', 'REFUNDED')):
--       * Nghiêm cấm thay đổi amount, method, paid_at, session_id, ticket_id, renewal_id,
--         hoặc code (check_violation, PROP-PAY-SETTLED-IMMUTABLE).
--       * Cho phép cập nhật notes (thông tin đối soát nghiệp vụ).
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_payment_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- 0. Không cho phép sửa đổi hoặc chuyển trạng thái thanh toán đã xoá mềm khi chưa khôi phục
    IF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'Không thể cập nhật hoặc chuyển trạng thái chứng từ thanh toán đang trong thùng rác.'
            USING ERRCODE = 'check_violation',
                  HINT = 'Cannot mutate a soft-deleted payment without restoring it first (TL-26, TL-42).';
    END IF;

    -- Không cho phép chuyển trạng thái sang PAID hoặc REFUNDED đối với thanh toán đã xoá mềm
    IF NEW.status IN ('PAID', 'REFUNDED') AND (NEW.deleted_at IS NOT NULL OR OLD.deleted_at IS NOT NULL) THEN
        RAISE EXCEPTION 'Chứng từ thanh toán đã thanh toán hoặc hoàn tiền không được phép ở trạng thái xóa mềm.'
            USING ERRCODE = 'check_violation',
                  HINT = 'Settled payment cannot be soft-deleted (PROP-DEL-PAYMENT-SETTLED, TL-39, TL-42).';
    END IF;

    -- 1. Kiểm tra tính hợp lệ khi trạng thái thanh toán thay đổi
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        -- Tuyệt đối không cho phép chuyển trạng thái quay lại UNPAID
        IF NEW.status = 'UNPAID' THEN
            RAISE EXCEPTION 'Không thể chuyển trạng thái thanh toán ngược về chưa thanh toán (UNPAID).'
                USING ERRCODE = 'check_violation',
                      HINT = format('Invalid payment status transition from %s to %s (PROP-PAY-STATUS-TRANSITION, TL-42).', OLD.status, NEW.status);
        END IF;

        -- Chuyển đổi từ UNPAID: chỉ cho phép chuyển sang PAID hoặc CANCELLED
        IF OLD.status = 'UNPAID' THEN
            IF NEW.status NOT IN ('PAID', 'CANCELLED') THEN
                RAISE EXCEPTION 'Chuyển đổi trạng thái thanh toán không hợp lệ từ % sang %.', OLD.status, NEW.status
                    USING ERRCODE = 'check_violation',
                          HINT = format('Invalid payment status transition from %s to %s (PROP-PAY-STATUS-TRANSITION, TL-42).', OLD.status, NEW.status);
            END IF;

        -- Chuyển đổi từ PAID: chỉ cho phép chuyển sang REFUNDED
        ELSIF OLD.status = 'PAID' THEN
            IF NEW.status <> 'REFUNDED' THEN
                RAISE EXCEPTION 'Chuyển đổi trạng thái thanh toán không hợp lệ từ % sang %.', OLD.status, NEW.status
                    USING ERRCODE = 'check_violation',
                          HINT = format('Invalid payment status transition from %s to %s (PROP-PAY-STATUS-TRANSITION, TL-42).', OLD.status, NEW.status);
            END IF;

        -- Trạng thái kết thúc: CANCELLED và REFUNDED không thể chuyển sang trạng thái nào khác
        ELSIF OLD.status IN ('CANCELLED', 'REFUNDED') THEN
            RAISE EXCEPTION 'Chứng từ thanh toán ở trạng thái kết thúc (%) không thể chuyển sang trạng thái khác (%).', OLD.status, NEW.status
                USING ERRCODE = 'check_violation',
                      HINT = format('Invalid payment status transition from %s to %s (PROP-PAY-STATUS-TRANSITION, TL-42).', OLD.status, NEW.status);
        END IF;
    END IF;

    -- 2. Thực thi tính bất biến đối với thanh toán đã tất toán hoặc đã hoàn tiền
    IF OLD.status IN ('PAID', 'REFUNDED') THEN
        IF OLD.amount IS DISTINCT FROM NEW.amount
           OR OLD.method IS DISTINCT FROM NEW.method
           OR OLD.paid_at IS DISTINCT FROM NEW.paid_at
           OR OLD.session_id IS DISTINCT FROM NEW.session_id
           OR OLD.ticket_id IS DISTINCT FROM NEW.ticket_id
           OR OLD.renewal_id IS DISTINCT FROM NEW.renewal_id
           OR OLD.reservation_id IS DISTINCT FROM NEW.reservation_id
           OR OLD.code IS DISTINCT FROM NEW.code THEN
            RAISE EXCEPTION 'Không thể chỉnh sửa thông tin tài chính hoặc liên kết của chứng từ thanh toán đã thanh toán hoặc đã hoàn tiền.'
                USING ERRCODE = 'check_violation',
                      HINT = 'Settled payment financial and link columns are immutable (PROP-PAY-SETTLED-IMMUTABLE, TL-42).';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_guard_payment_update() IS 'Kiểm soát chuyển đổi trạng thái thanh toán và thực thi tính bất biến cho thanh toán đã tất toán.';

CREATE TRIGGER trg_guard_payment_update
    BEFORE UPDATE ON payment
    FOR EACH ROW EXECUTE FUNCTION fn_guard_payment_update();

-- -----------------------------------------------------------------------------
-- 8.18. Hàm trigger: fn_guard_slot_reservation_status_transition()
-- Thực thi chuyển đổi trạng thái vòng đời hợp lệ và tính bất biến cho slot_reservation:
--   - PENDING_PAYMENT -> CONFIRMED, CANCELLED, EXPIRED
--   - CONFIRMED -> CHECKED_IN, CANCELLED, NO_SHOW
--   - CHECKED_IN -> COMPLETED
--   - Các trạng thái kết thúc (COMPLETED, CANCELLED, EXPIRED, NO_SHOW) không thể chuyển sang trạng thái khác.
--   - Các thông số đặt chỗ cốt lõi (slot_id, customer_id, vehicle_id, reserved_from, reserved_until)
--     là bất biến khi đã ở trạng thái kết thúc.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_guard_slot_reservation_status_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Tính bất biến của trạng thái kết thúc: một khi đã completed/cancelled/expired/no_show thì không thể đổi trạng thái
    IF OLD.status IN ('COMPLETED', 'CANCELLED', 'EXPIRED', 'NO_SHOW') THEN
        IF NEW.status IS DISTINCT FROM OLD.status THEN
            RAISE EXCEPTION 'Đặt chỗ ở trạng thái kết thúc (%) không thể chuyển sang trạng thái khác (%).', OLD.status, NEW.status
                USING ERRCODE = 'check_violation',
                      HINT = format('Terminal reservation status %s is immutable (PROP-BOOK-TERMINAL-IMMUTABLE).', OLD.status);
        END IF;

        IF OLD.slot_id IS DISTINCT FROM NEW.slot_id
           OR OLD.customer_id IS DISTINCT FROM NEW.customer_id
           OR OLD.vehicle_id IS DISTINCT FROM NEW.vehicle_id
           OR OLD.reserved_from IS DISTINCT FROM NEW.reserved_from
           OR OLD.reserved_until IS DISTINCT FROM NEW.reserved_until
           OR OLD.code IS DISTINCT FROM NEW.code THEN
            RAISE EXCEPTION 'Không thể chỉnh sửa thông tin lịch đặt chỗ đã ở trạng thái kết thúc (%).', OLD.status
                USING ERRCODE = 'check_violation',
                      HINT = 'Terminal reservation parameters are immutable (PROP-BOOK-TERMINAL-FIELDS-IMMUTABLE).';
        END IF;
    END IF;

    IF OLD.status IS DISTINCT FROM NEW.status THEN
        -- Không cho phép chuyển ngược về PENDING_PAYMENT
        IF NEW.status = 'PENDING_PAYMENT' THEN
            RAISE EXCEPTION 'Không thể chuyển trạng thái đặt chỗ ngược về chờ thanh toán (PENDING_PAYMENT).'
                USING ERRCODE = 'check_violation',
                      HINT = format('Invalid reservation status transition from %s to %s (PROP-BOOK-STATUS-TRANSITION).', OLD.status, NEW.status);
        END IF;

        -- Chuyển đổi hợp lệ từ PENDING_PAYMENT: CONFIRMED, CANCELLED, EXPIRED
        IF OLD.status = 'PENDING_PAYMENT' THEN
            IF NEW.status NOT IN ('CONFIRMED', 'CANCELLED', 'EXPIRED') THEN
                RAISE EXCEPTION 'Chuyển đổi trạng thái đặt chỗ không hợp lệ từ % sang %.', OLD.status, NEW.status
                    USING ERRCODE = 'check_violation',
                          HINT = format('Invalid reservation status transition from %s to %s (PROP-BOOK-STATUS-TRANSITION).', OLD.status, NEW.status);
            END IF;

        -- Chuyển đổi hợp lệ từ CONFIRMED: CHECKED_IN, CANCELLED, NO_SHOW
        ELSIF OLD.status = 'CONFIRMED' THEN
            IF NEW.status NOT IN ('CHECKED_IN', 'CANCELLED', 'NO_SHOW') THEN
                RAISE EXCEPTION 'Chuyển đổi trạng thái đặt chỗ không hợp lệ từ % sang %.', OLD.status, NEW.status
                    USING ERRCODE = 'check_violation',
                          HINT = format('Invalid reservation status transition from %s to %s (PROP-BOOK-STATUS-TRANSITION).', OLD.status, NEW.status);
            END IF;

        -- Chuyển đổi hợp lệ từ CHECKED_IN: COMPLETED
        ELSIF OLD.status = 'CHECKED_IN' THEN
            IF NEW.status <> 'COMPLETED' THEN
                RAISE EXCEPTION 'Chuyển đổi trạng thái đặt chỗ không hợp lệ từ % sang %.', OLD.status, NEW.status
                    USING ERRCODE = 'check_violation',
                          HINT = format('Invalid reservation status transition from %s to %s (PROP-BOOK-STATUS-TRANSITION).', OLD.status, NEW.status);
            END IF;
        END IF;

        -- Tự động điền các mốc thời gian vòng đời
        IF NEW.status = 'CHECKED_IN' AND NEW.checked_in_at IS NULL THEN
            NEW.checked_in_at := CURRENT_TIMESTAMP;
        ELSIF NEW.status = 'COMPLETED' AND NEW.completed_at IS NULL THEN
            NEW.completed_at := CURRENT_TIMESTAMP;
        ELSIF NEW.status = 'CANCELLED' AND NEW.cancelled_at IS NULL THEN
            NEW.cancelled_at := CURRENT_TIMESTAMP;
        ELSIF NEW.status = 'NO_SHOW' AND NEW.no_show_at IS NULL THEN
            NEW.no_show_at := CURRENT_TIMESTAMP;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_guard_slot_reservation_status_transition() IS 'Kiểm soát chuyển đổi trạng thái đặt chỗ, bảo đảm tính bất biến của trạng thái kết thúc và tự động điền các mốc thời gian vòng đời.';

CREATE TRIGGER trg_guard_slot_reservation_status_transition
    BEFORE UPDATE ON slot_reservation
    FOR EACH ROW EXECUTE FUNCTION fn_guard_slot_reservation_status_transition();

-- -----------------------------------------------------------------------------
-- 8.19. Hàm trigger: fn_sync_reservation_on_payment()
-- Tự động chuyển slot_reservation từ PENDING_PAYMENT sang CONFIRMED
-- khi chứng từ cọc tương ứng chuyển sang PAID.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_sync_reservation_on_payment()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.reservation_id IS NOT NULL AND NEW.status = 'PAID' THEN
        UPDATE slot_reservation
        SET status = 'CONFIRMED',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.reservation_id
          AND status = 'PENDING_PAYMENT'
          AND deleted_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION fn_sync_reservation_on_payment() IS 'Tự động chuyển đặt chỗ từ PENDING_PAYMENT sang CONFIRMED khi chứng từ cọc tương ứng được thanh toán PAID.';

CREATE TRIGGER trg_sync_reservation_on_payment
    AFTER INSERT OR UPDATE OF status ON payment
    FOR EACH ROW
    WHEN (NEW.reservation_id IS NOT NULL AND NEW.status = 'PAID')
    EXECUTE FUNCTION fn_sync_reservation_on_payment();

-- Thắt chặt quyền hạn: thu hồi quyền PUBLIC EXECUTE trực tiếp trên toàn bộ 17 hàm trigger nội bộ
REVOKE ALL ON FUNCTION
    fn_update_row_version_and_timestamp(),
    fn_guard_parking_slot_status(),
    fn_sync_ticket_status(),
    fn_guard_slot_reservation_write(),
    fn_guard_slot_reservation_on_entry(),
    fn_sync_slot_status_on_traffic(),
    fn_sync_slot_status_on_ticket(),
    fn_sync_slot_status_on_reservation(),
    fn_prevent_activity_log_mutation(),
    fn_guard_hard_immutable_table(),
    fn_guard_slot_allowed_vehicle_type_delete(),
    fn_guard_prevent_plain_delete(),
    fn_guard_soft_delete_and_restore(),
    fn_audit_soft_delete_and_restore(),
    fn_guard_payment_update(),
    fn_guard_slot_reservation_status_transition(),
    fn_sync_reservation_on_payment()
FROM PUBLIC;

-- =============================================================================
-- PHẦN 9: CÁC VIEW PHÂN TÍCH VÀ DASHBOARD
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 9.1. View: v_slot_occupancy_by_floor (Sức chứa và mức sử dụng ô đỗ)
-- -----------------------------------------------------------------------------
CREATE VIEW v_slot_occupancy_by_floor AS
-- Bảng tạm open_sessions: Ô đang có xe đỗ (phiên chưa ra; xe và khách chưa bị xoá mềm)
WITH open_sessions AS (
    SELECT DISTINCT l.slot_id
    FROM vehicle_entry_exit_log l
    LEFT JOIN vehicle v ON v.id = l.vehicle_id
    LEFT JOIN customer c ON c.id = v.customer_id
    WHERE l.exit_time IS NULL
      AND l.slot_id IS NOT NULL
      AND (l.vehicle_id IS NULL OR (v.deleted_at IS NULL AND c.deleted_at IS NULL))
),
-- Bảng tạm active_tickets: Ô đang có vé hiệu lực (ACTIVE hoặc RENEWING, còn hạn)
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
-- Bảng tạm active_reservations: Ô đang được đặt chỗ (chờ thanh toán hoặc đã xác nhận, chưa hết hạn)
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
-- Bảng tạm slot_states: Trạng thái hiệu lực của từng ô, tính từ phiên đỗ, vé và đặt chỗ
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
-- 9.2. View: v_revenue_today_by_method (Doanh thu hôm nay theo hình thức thanh toán)
-- -----------------------------------------------------------------------------
CREATE VIEW v_revenue_today_by_method AS
-- Bảng tạm today_payments: Các chứng từ đã thanh toán (PAID) trong ngày hôm nay
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
-- 9.3. View: v_traffic_by_hour (Lượt xe vào/ra theo giờ)
-- -----------------------------------------------------------------------------
CREATE VIEW v_traffic_by_hour AS
-- Bảng tạm active_sessions: Các phiên ra/vào hợp lệ (ô, xe, khách, vé liên quan chưa bị xoá mềm)
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
-- Bảng tạm entry_hours: Số lượt xe vào theo từng giờ
entry_hours AS (
    SELECT
        DATE_TRUNC('hour', entry_time) AS traffic_hour,
        COUNT(*)::BIGINT AS entry_count
    FROM active_sessions
    GROUP BY DATE_TRUNC('hour', entry_time)
),
-- Bảng tạm exit_hours: Số lượt xe ra theo từng giờ
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
-- 9.4. View: v_ai_recognition_stats (Tỷ lệ nhận diện biển số bằng AI)
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
-- 9.5. View: v_customer_status_summary (Số khách theo trạng thái)
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
-- 9.6. View: v_revenue_statistics (Doanh thu theo năm, quý, tháng)
-- -----------------------------------------------------------------------------
CREATE VIEW v_revenue_statistics AS
-- Bảng tạm financial_events: Các khoản doanh thu: tiền vé và phí gia hạn, gộp bằng UNION ALL
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
-- 9.7. View: v_vehicle_traffic_daily (Lượt xe vào/ra theo ngày)
-- -----------------------------------------------------------------------------
CREATE VIEW v_vehicle_traffic_daily AS
-- Bảng tạm active_sessions: Các phiên ra/vào hợp lệ (ô, xe, khách, vé liên quan chưa bị xoá mềm)
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
-- Bảng tạm entry_daily: Số lượt vào và số xe đang đỗ theo từng ngày
entry_daily AS (
    SELECT
        entry_time::DATE AS traffic_date,
        COUNT(*)::BIGINT AS total_entries,
        COUNT(*) FILTER (WHERE exit_time IS NULL)::BIGINT AS currently_parked_count
    FROM active_sessions
    GROUP BY entry_time::DATE
),
-- Bảng tạm exit_daily: Số lượt xe ra theo từng ngày
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
-- 9.8. View: v_customer_vehicle_summary (Số xe và vé của mỗi khách)
-- -----------------------------------------------------------------------------
CREATE VIEW v_customer_vehicle_summary AS
-- Bảng tạm vehicle_counts: Số xe đã đăng ký của mỗi khách hàng
WITH vehicle_counts AS (
    SELECT
        v.customer_id,
        COUNT(*)::BIGINT AS total_registered_vehicles
    FROM vehicle v
    JOIN vehicle_type vt ON vt.id = v.vehicle_type_id AND vt.deleted_at IS NULL
    WHERE v.deleted_at IS NULL
    GROUP BY v.customer_id
),
-- Bảng tạm ticket_counts: Số vé đang hiệu lực của mỗi khách hàng
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
-- PHẦN 10: CÁC HÀM THỐNG KÊ THEO KHOẢNG THỜI GIAN
-- =============================================================================

CREATE FUNCTION fn_stat_vehicles_by_day(p_from_date DATE, p_to_date DATE)
RETURNS TABLE (
    traffic_date DATE,
    total_entries BIGINT,
    total_exits BIGINT,
    distinct_vehicles BIGINT
)
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_from_date IS NULL OR p_to_date IS NULL OR p_from_date > p_to_date THEN
        RAISE EXCEPTION 'Khoảng thời gian thống kê không hợp lệ (Từ ngày phải nhỏ hơn hoặc bằng Đến ngày).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    SELECT
        l.entry_time::DATE AS traffic_date,
        COUNT(*)::BIGINT AS total_entries,
        COUNT(*) FILTER (WHERE l.exit_time IS NOT NULL AND l.exit_time::DATE BETWEEN p_from_date AND p_to_date)::BIGINT AS total_exits,
        COUNT(DISTINCT l.license_plate_norm)::BIGINT AS distinct_vehicles
    FROM vehicle_entry_exit_log l
    LEFT JOIN parking_slot ps ON ps.id = l.slot_id
    LEFT JOIN vehicle v ON v.id = l.vehicle_id
    LEFT JOIN customer c ON c.id = v.customer_id
    LEFT JOIN ticket t ON t.id = l.ticket_id
    WHERE l.entry_time::DATE BETWEEN p_from_date AND p_to_date
      AND (l.slot_id IS NULL OR ps.deleted_at IS NULL)
      AND (l.vehicle_id IS NULL OR (v.deleted_at IS NULL AND c.deleted_at IS NULL))
      AND (l.ticket_id IS NULL OR t.deleted_at IS NULL)
    GROUP BY l.entry_time::DATE
    ORDER BY traffic_date DESC;
END;
$$;

COMMENT ON FUNCTION fn_stat_vehicles_by_day(DATE, DATE) IS 'Thống kê lưu lượng xe theo từng ngày trong khoảng thời gian, loại trừ các thực thể đã bị xoá mềm.';

CREATE FUNCTION fn_stat_vehicles_by_floor(p_from_date DATE, p_to_date DATE)
RETURNS TABLE (
    floor_id BIGINT,
    floor_code VARCHAR(20),
    floor_name VARCHAR(50),
    entry_count BIGINT,
    distinct_vehicle_count BIGINT,
    ticket_count BIGINT
)
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_from_date IS NULL OR p_to_date IS NULL OR p_from_date > p_to_date THEN
        RAISE EXCEPTION 'Khoảng thời gian thống kê không hợp lệ (Từ ngày phải nhỏ hơn hoặc bằng Đến ngày).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    WITH floor_logs AS (
        SELECT
            pf.id AS f_id,
            COUNT(l.id)::BIGINT AS entry_cnt,
            COUNT(DISTINCT l.license_plate_norm)::BIGINT AS distinct_veh_cnt
        FROM parking_floor pf
        JOIN parking_lot pl ON pl.id = pf.lot_id AND pl.deleted_at IS NULL
        JOIN parking_zone pz ON pz.floor_id = pf.id AND pz.deleted_at IS NULL
        JOIN parking_slot ps ON ps.zone_id = pz.id AND ps.deleted_at IS NULL
        LEFT JOIN vehicle_entry_exit_log l
            ON l.slot_id = ps.id
           AND l.entry_time::DATE BETWEEN p_from_date AND p_to_date
           AND NOT EXISTS (
               SELECT 1
               FROM vehicle v
               LEFT JOIN customer c ON c.id = v.customer_id
               WHERE v.id = l.vehicle_id
                 AND (v.deleted_at IS NOT NULL OR c.deleted_at IS NOT NULL)
           )
           AND NOT EXISTS (
               SELECT 1
               FROM ticket lt
               WHERE lt.id = l.ticket_id
                 AND lt.deleted_at IS NOT NULL
           )
        WHERE pf.deleted_at IS NULL
        GROUP BY pf.id
    ),
    floor_tickets AS (
        SELECT
            pf.id AS f_id,
            COUNT(t.id)::BIGINT AS ticket_cnt
        FROM parking_floor pf
        JOIN parking_lot pl ON pl.id = pf.lot_id AND pl.deleted_at IS NULL
        JOIN parking_zone pz ON pz.floor_id = pf.id AND pz.deleted_at IS NULL
        JOIN parking_slot ps ON ps.zone_id = pz.id AND ps.deleted_at IS NULL
        LEFT JOIN ticket t
            ON t.slot_id = ps.id
           AND t.deleted_at IS NULL
           AND t.created_at::DATE BETWEEN p_from_date AND p_to_date
           AND EXISTS (
               SELECT 1
               FROM vehicle v
               JOIN customer c ON c.id = v.customer_id AND c.deleted_at IS NULL
               WHERE v.id = t.vehicle_id
                 AND v.deleted_at IS NULL
           )
        WHERE pf.deleted_at IS NULL
        GROUP BY pf.id
    )
    SELECT
        pf.id AS floor_id,
        pf.code AS floor_code,
        pf.name AS floor_name,
        COALESCE(fl.entry_cnt, 0)::BIGINT AS entry_count,
        COALESCE(fl.distinct_veh_cnt, 0)::BIGINT AS distinct_vehicle_count,
        COALESCE(ft.ticket_cnt, 0)::BIGINT AS ticket_count
    FROM parking_floor pf
    JOIN parking_lot pl ON pl.id = pf.lot_id AND pl.deleted_at IS NULL
    LEFT JOIN floor_logs fl ON fl.f_id = pf.id
    LEFT JOIN floor_tickets ft ON ft.f_id = pf.id
    WHERE pf.deleted_at IS NULL
    ORDER BY pf.sort_order ASC, pf.id ASC;
END;
$$;

COMMENT ON FUNCTION fn_stat_vehicles_by_floor(DATE, DATE) IS 'Thống kê lượt đỗ và vé phân bổ theo từng tầng trong khoảng thời gian, loại trừ bản ghi đã xoá mềm.';

CREATE FUNCTION fn_stat_vehicles_by_customer(p_from_date DATE, p_to_date DATE)
RETURNS TABLE (
    customer_id BIGINT,
    customer_code VARCHAR(10),
    customer_name VARCHAR(45),
    registered_vehicle_count BIGINT,
    period_ticket_count BIGINT
)
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_from_date IS NULL OR p_to_date IS NULL OR p_from_date > p_to_date THEN
        RAISE EXCEPTION 'Khoảng thời gian thống kê không hợp lệ (Từ ngày phải nhỏ hơn hoặc bằng Đến ngày).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    WITH cust_vehicles AS (
        SELECT
            v.customer_id AS c_id,
            COUNT(v.id)::BIGINT AS veh_cnt
        FROM vehicle v
        JOIN vehicle_type vt ON vt.id = v.vehicle_type_id AND vt.deleted_at IS NULL
        WHERE v.deleted_at IS NULL
        GROUP BY v.customer_id
    ),
    cust_tickets AS (
        SELECT
            t.customer_id AS c_id,
            COUNT(t.id)::BIGINT AS tkt_cnt
        FROM ticket t
        JOIN vehicle v ON v.id = t.vehicle_id AND v.deleted_at IS NULL
        JOIN parking_slot ps ON ps.id = t.slot_id AND ps.deleted_at IS NULL
        WHERE t.deleted_at IS NULL
          AND t.created_at::DATE BETWEEN p_from_date AND p_to_date
        GROUP BY t.customer_id
    )
    SELECT
        c.id AS customer_id,
        c.code AS customer_code,
        c.full_name AS customer_name,
        COALESCE(cv.veh_cnt, 0)::BIGINT AS registered_vehicle_count,
        COALESCE(ct.tkt_cnt, 0)::BIGINT AS period_ticket_count
    FROM customer c
    LEFT JOIN cust_vehicles cv ON cv.c_id = c.id
    LEFT JOIN cust_tickets ct ON ct.c_id = c.id
    WHERE c.deleted_at IS NULL
    ORDER BY period_ticket_count DESC, c.id ASC;
END;
$$;

COMMENT ON FUNCTION fn_stat_vehicles_by_customer(DATE, DATE) IS 'Thống kê số lượng xe đăng ký và vé mua của khách hàng trong khoảng thời gian, loại trừ bản ghi đã xoá mềm.';

CREATE FUNCTION fn_stat_revenue_by_period(p_from_date DATE, p_to_date DATE)
RETURNS TABLE (
    report_year INTEGER,
    report_quarter INTEGER,
    report_month INTEGER,
    total_tickets_sold BIGINT,
    total_renewals BIGINT,
    total_revenue NUMERIC(12, 2)
)
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_from_date IS NULL OR p_to_date IS NULL OR p_from_date > p_to_date THEN
        RAISE EXCEPTION 'Khoảng thời gian thống kê không hợp lệ (Từ ngày phải nhỏ hơn hoặc bằng Đến ngày).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    WITH period_events AS (
        SELECT
            EXTRACT(YEAR FROM t.created_at)::INTEGER AS r_year,
            EXTRACT(QUARTER FROM t.created_at)::INTEGER AS r_quarter,
            EXTRACT(MONTH FROM t.created_at)::INTEGER AS r_month,
            1::BIGINT AS t_cnt,
            0::BIGINT AS r_cnt,
            t.price AS amt
        FROM ticket t
        JOIN customer c ON c.id = t.customer_id AND c.deleted_at IS NULL
        JOIN vehicle v ON v.id = t.vehicle_id AND v.deleted_at IS NULL
        JOIN parking_slot ps ON ps.id = t.slot_id AND ps.deleted_at IS NULL
        WHERE t.deleted_at IS NULL
          AND t.created_at::DATE BETWEEN p_from_date AND p_to_date
          AND NOT EXISTS (
              SELECT 1
              FROM payment p
              WHERE p.ticket_id = t.id
                AND p.deleted_at IS NOT NULL
          )
        UNION ALL
        SELECT
            EXTRACT(YEAR FROM tr.created_at)::INTEGER AS r_year,
            EXTRACT(QUARTER FROM tr.created_at)::INTEGER AS r_quarter,
            EXTRACT(MONTH FROM tr.created_at)::INTEGER AS r_month,
            0::BIGINT AS t_cnt,
            1::BIGINT AS r_cnt,
            tr.additional_price AS amt
        FROM ticket_renewal tr
        JOIN ticket t ON t.id = tr.ticket_id AND t.deleted_at IS NULL
        JOIN customer c ON c.id = t.customer_id AND c.deleted_at IS NULL
        JOIN vehicle v ON v.id = t.vehicle_id AND v.deleted_at IS NULL
        JOIN parking_slot ps ON ps.id = t.slot_id AND ps.deleted_at IS NULL
        WHERE tr.created_at::DATE BETWEEN p_from_date AND p_to_date
          AND NOT EXISTS (
              SELECT 1
              FROM payment p
              WHERE p.renewal_id = tr.id
                AND p.deleted_at IS NOT NULL
          )
    )
    SELECT
        pe.r_year AS report_year,
        pe.r_quarter AS report_quarter,
        pe.r_month AS report_month,
        SUM(pe.t_cnt)::BIGINT AS total_tickets_sold,
        SUM(pe.r_cnt)::BIGINT AS total_renewals,
        COALESCE(SUM(pe.amt), 0.00)::NUMERIC(12, 2) AS total_revenue
    FROM period_events pe
    GROUP BY pe.r_year, pe.r_quarter, pe.r_month
    ORDER BY report_year DESC, report_quarter DESC, report_month DESC;
END;
$$;

COMMENT ON FUNCTION fn_stat_revenue_by_period(DATE, DATE) IS 'Tổng hợp doanh thu tài chính từ vé và gia hạn vé trong khoảng thời gian, loại trừ bản ghi đã xoá mềm.';

-- =============================================================================
-- PHẦN 11: QUẢN LÝ ĐẶT CHỖ TRƯỚC
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 11.1. View: v_booking_overview (Tổng quan các lượt đặt chỗ)
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

-- -----------------------------------------------------------------------------
-- 11.2. Hàm: fn_find_available_slots()
-- Tìm kiếm các ô đỗ còn trống theo bãi xe, loại xe và khoảng thời gian
-- mà không bị trùng đặt chỗ hoặc vé.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_find_available_slots(
    p_lot_id BIGINT,
    p_vehicle_type_id BIGINT,
    p_from TIMESTAMPTZ,
    p_until TIMESTAMPTZ,
    p_floor_id BIGINT DEFAULT NULL
)
RETURNS TABLE (
    slot_id BIGINT,
    slot_code VARCHAR(20),
    floor_id BIGINT,
    floor_code VARCHAR(20),
    floor_name VARCHAR(50),
    zone_id BIGINT,
    zone_code VARCHAR(20),
    zone_name VARCHAR(50),
    slot_kind VARCHAR(30)
)
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_from IS NULL OR p_until IS NULL OR p_from >= p_until THEN
        RAISE EXCEPTION 'Khoảng thời gian tìm kiếm không hợp lệ (thời gian bắt đầu phải trước thời gian kết thúc).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    SELECT
        ps.id AS slot_id,
        ps.code AS slot_code,
        pf.id AS floor_id,
        pf.code AS floor_code,
        pf.name AS floor_name,
        pz.id AS zone_id,
        pz.code AS zone_code,
        pz.name AS zone_name,
        ps.slot_kind
    FROM parking_slot ps
    JOIN parking_zone pz ON pz.id = ps.zone_id AND pz.deleted_at IS NULL
    JOIN parking_floor pf ON pf.id = pz.floor_id AND pf.deleted_at IS NULL
    JOIN parking_lot pl ON pl.id = pf.lot_id AND pl.deleted_at IS NULL
    WHERE pl.id = p_lot_id
      AND (p_floor_id IS NULL OR pf.id = p_floor_id)
      AND ps.deleted_at IS NULL
      AND ps.status <> 'MAINTENANCE'
      -- Kiểm tra loại xe: nếu ô đỗ có cấu hình giới hạn loại xe thì phải khớp với p_vehicle_type_id
      AND (
          p_vehicle_type_id IS NULL
          OR EXISTS (
              SELECT 1 FROM slot_allowed_vehicle_type savt
              WHERE savt.slot_id = ps.id AND savt.vehicle_type_id = p_vehicle_type_id
          )
      )
      -- Không bị trùng với đặt chỗ đang hoạt động
      AND NOT EXISTS (
          SELECT 1
          FROM slot_reservation r
          WHERE r.slot_id = ps.id
            AND r.deleted_at IS NULL
            AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN')
            AND tstzrange(r.reserved_from, r.reserved_until, '[)') && tstzrange(p_from, p_until, '[)')
      )
      -- Không bị trùng với vé đang hiệu lực
      AND NOT EXISTS (
          SELECT 1
          FROM ticket t
          WHERE t.slot_id = ps.id
            AND t.deleted_at IS NULL
            AND t.status IN ('ACTIVE', 'RENEWING')
            AND tstzrange(t.effective_from, t.effective_to, '[)') && tstzrange(p_from, p_until, '[)')
      )
      -- Nếu khoảng thời gian giao thoa với thời điểm hiện tại, bảo đảm ô không có xe đang đỗ
      AND (
          NOT (p_from <= CURRENT_TIMESTAMP AND p_until > CURRENT_TIMESTAMP)
          OR NOT EXISTS (
              SELECT 1 FROM vehicle_entry_exit_log l
              WHERE l.slot_id = ps.id AND l.exit_time IS NULL
          )
      )
    ORDER BY pf.sort_order ASC, pz.code ASC, ps.code ASC;
END;
$$;

COMMENT ON FUNCTION fn_find_available_slots(BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, BIGINT) IS 'Tìm các ô đỗ còn trống theo bãi xe, loại xe, khung thời gian và bộ lọc tầng tuỳ chọn mà không bị trùng vé hoặc đặt chỗ.';

-- -----------------------------------------------------------------------------
-- 11.3. Hàm: fn_create_booking()
-- Tạo yêu cầu đặt chỗ trước: kiểm tra chính sách, độ phù hợp của xe,
-- danh sách đen, chống trùng lịch và tạo chứng từ cọc.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_create_booking(
    p_lot_id BIGINT,
    p_customer_id BIGINT,
    p_vehicle_id BIGINT,
    p_slot_id BIGINT,
    p_reserved_from TIMESTAMPTZ,
    p_reserved_until TIMESTAMPTZ,
    p_booking_channel VARCHAR(20) DEFAULT 'CUSTOMER_PORTAL',
    p_reserved_name VARCHAR(100) DEFAULT NULL,
    p_reserved_phone VARCHAR(15) DEFAULT NULL,
    p_notes TEXT DEFAULT NULL,
    p_created_by BIGINT DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_policy RECORD;
    v_slot RECORD;
    v_customer RECORD;
    v_vehicle RECORD;
    v_reservation_id BIGINT;
    v_code VARCHAR(30);
    v_deposit_amount NUMERIC(12, 2);
    v_initial_status VARCHAR(20);
    v_hold_expires TIMESTAMPTZ;
    v_duration_minutes NUMERIC;
    v_constraint_name TEXT;
BEGIN
    -- 1. Kiểm tra tính hợp lệ của các tham số thời gian
    IF p_reserved_from IS NULL OR p_reserved_until IS NULL OR p_reserved_from >= p_reserved_until THEN
        RAISE EXCEPTION 'Thời gian đặt chỗ không hợp lệ (thời gian bắt đầu phải trước thời gian kết thúc).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_reserved_from < CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Thời gian bắt đầu đặt chỗ không được ở trong quá khứ.'
            USING ERRCODE = 'check_violation',
                  HINT = 'PROP-BOOK-RESERVE-IN-PAST';
    END IF;

    -- 2. Xác minh ô đỗ tồn tại, thuộc đúng bãi xe và không bảo trì
    SELECT ps.*, pz.floor_id, pf.lot_id
    INTO v_slot
    FROM parking_slot ps
    JOIN parking_zone pz ON pz.id = ps.zone_id AND pz.deleted_at IS NULL
    JOIN parking_floor pf ON pf.id = pz.floor_id AND pf.deleted_at IS NULL
    WHERE ps.id = p_slot_id AND ps.deleted_at IS NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Vị trí đỗ xe (ID: %) không tồn tại hoặc đã bị xóa.', p_slot_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_slot.lot_id <> p_lot_id THEN
        RAISE EXCEPTION 'Vị trí đỗ xe không thuộc bãi đỗ xe đã chọn.'
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_slot.status = 'MAINTENANCE' THEN
        RAISE EXCEPTION 'Vị trí đỗ xe đang bảo trì, không thể đặt trước.'
            USING ERRCODE = 'check_violation';
    END IF;

    -- 3. Lấy chính sách đặt chỗ của bãi (áp dụng giá trị mặc định nếu chưa cấu hình)
    SELECT * INTO v_policy
    FROM booking_policy
    WHERE lot_id = p_lot_id AND deleted_at IS NULL AND is_active = TRUE;

    IF NOT FOUND THEN
        -- Các giá trị chính sách mặc định của hệ thống
        v_policy.hold_minutes := 15;
        v_policy.grace_minutes := 15;
        v_policy.early_checkin_minutes := 15;
        v_policy.max_advance_days := 7;
        v_policy.min_duration_minutes := 30;
        v_policy.max_duration_minutes := 1440;
        v_policy.deposit_amount := 50000.00;
        v_policy.cancel_free_before_minutes := 60;
    END IF;

    -- 4. Kiểm tra khung thời gian và thời lượng đặt chỗ theo chính sách
    v_duration_minutes := EXTRACT(EPOCH FROM (p_reserved_until - p_reserved_from)) / 60.0;
    IF v_duration_minutes < v_policy.min_duration_minutes THEN
        RAISE EXCEPTION 'Thời lượng đặt chỗ (% phút) ngắn hơn mức tối thiểu quy định (% phút).', v_duration_minutes, v_policy.min_duration_minutes
            USING ERRCODE = 'check_violation',
                  HINT = 'PROP-BOOK-MIN-DURATION';
    END IF;

    IF v_duration_minutes > v_policy.max_duration_minutes THEN
        RAISE EXCEPTION 'Thời lượng đặt chỗ (% phút) vượt quá mức tối đa quy định (% phút).', v_duration_minutes, v_policy.max_duration_minutes
            USING ERRCODE = 'check_violation',
                  HINT = 'PROP-BOOK-MAX-DURATION';
    END IF;

    IF p_reserved_from > CURRENT_TIMESTAMP + (v_policy.max_advance_days * INTERVAL '1 day') THEN
        RAISE EXCEPTION 'Thời gian đặt chỗ vượt quá số ngày đặt trước tối đa cho phép (% ngày).', v_policy.max_advance_days
            USING ERRCODE = 'check_violation',
                  HINT = 'PROP-BOOK-MAX-ADVANCE';
    END IF;

    -- 5. Kiểm tra thông tin khách hàng và danh sách đen
    IF p_customer_id IS NOT NULL THEN
        SELECT * INTO v_customer
        FROM customer
        WHERE id = p_customer_id AND deleted_at IS NULL;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Khách hàng (ID: %) không tồn tại hoặc đã bị xóa.', p_customer_id
                USING ERRCODE = 'check_violation';
        END IF;

        IF v_customer.status IN ('BLACKLISTED', 'SUSPENDED') THEN
            RAISE EXCEPTION 'Khách hàng đang ở trạng thái khóa hoặc danh sách đen (BLACKLISTED/SUSPENDED), không thể thực hiện đặt chỗ.'
                USING ERRCODE = 'check_violation',
                      HINT = 'PROP-BOOK-CUSTOMER-BLACKLISTED';
        END IF;
    END IF;

    -- 6. Kiểm tra phương tiện và danh sách đen biển số
    IF p_vehicle_id IS NOT NULL THEN
        SELECT v.*, vt.name AS vehicle_type_name
        INTO v_vehicle
        FROM vehicle v
        JOIN vehicle_type vt ON vt.id = v.vehicle_type_id AND vt.deleted_at IS NULL
        WHERE v.id = p_vehicle_id AND v.deleted_at IS NULL;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Phương tiện (ID: %) không tồn tại hoặc đã bị xóa.', p_vehicle_id
                USING ERRCODE = 'check_violation';
        END IF;

        IF EXISTS (
            SELECT 1 FROM plate_blacklist pb
            WHERE pb.license_plate_norm = v_vehicle.license_plate_norm
              AND pb.deleted_at IS NULL
              AND pb.is_active = TRUE
        ) THEN
            RAISE EXCEPTION 'Biển số xe % đang trong danh sách đen, không thể đặt chỗ.', v_vehicle.license_plate
                USING ERRCODE = 'check_violation',
                      HINT = 'PROP-BOOK-PLATE-BLACKLISTED';
        END IF;

        -- Xác minh loại xe được phép đỗ tại ô này
        IF NOT EXISTS (
            SELECT 1 FROM slot_allowed_vehicle_type savt
            WHERE savt.slot_id = p_slot_id AND savt.vehicle_type_id = v_vehicle.vehicle_type_id
        ) THEN
            RAISE EXCEPTION 'Vị trí đỗ xe này không hỗ trợ loại xe %.', v_vehicle.vehicle_type_name
                USING ERRCODE = 'check_violation',
                      HINT = 'PROP-BOOK-SLOT-VEHICLE-TYPE-MISMATCH';
        END IF;
    END IF;

    -- 7. Tính toán số tiền cọc và trạng thái ban đầu
    v_deposit_amount := COALESCE(v_policy.deposit_amount, 0.00);
    IF v_deposit_amount > 0.00 THEN
        v_initial_status := 'PENDING_PAYMENT';
        v_hold_expires := CURRENT_TIMESTAMP + (v_policy.hold_minutes * INTERVAL '1 minute');
    ELSE
        v_initial_status := 'CONFIRMED';
        v_hold_expires := NULL;
    END IF;

    -- 8. Tạo mã đặt chỗ duy nhất
    v_code := 'RSV-' || TO_CHAR(CURRENT_TIMESTAMP, 'YYYYMMDD') || '-' || UPPER(SUBSTR(MD5(RANDOM()::TEXT || CLOCK_TIMESTAMP()::TEXT), 1, 6));

    -- 9. Thêm bản ghi slot_reservation và bắt lỗi trùng lặp ràng buộc loại trừ (23P01)
    BEGIN
        INSERT INTO slot_reservation (
            code,
            slot_id,
            customer_id,
            vehicle_id,
            booking_channel,
            reserved_name,
            reserved_phone,
            reserved_from,
            reserved_until,
            status,
            hold_expires_at,
            deposit_amount,
            notes,
            created_by
        ) VALUES (
            v_code,
            p_slot_id,
            p_customer_id,
            p_vehicle_id,
            p_booking_channel,
            p_reserved_name,
            p_reserved_phone,
            p_reserved_from,
            p_reserved_until,
            v_initial_status,
            v_hold_expires,
            v_deposit_amount,
            p_notes,
            p_created_by
        )
        RETURNING id INTO v_reservation_id;
    EXCEPTION
        WHEN exclusion_violation THEN
            GET STACKED DIAGNOSTICS v_constraint_name = CONSTRAINT_NAME;
            IF v_constraint_name = 'excl_reservation_vehicle_time_overlap' THEN
                RAISE EXCEPTION 'Phương tiện này đã có một lịch đặt chỗ khác trùng lặp về thời gian.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-BOOK-VEHICLE-DOUBLE-BOOKING';
            ELSE
                RAISE EXCEPTION 'Vị trí đỗ xe này đã có người đặt trước trong khung giờ đã chọn.'
                    USING ERRCODE = 'check_violation',
                          HINT = 'PROP-BOOK-SLOT-ALREADY-TAKEN';
            END IF;
    END;

    -- 10. Nếu cần đặt cọc, tạo chứng từ thanh toán UNPAID chờ xử lý
    IF v_deposit_amount > 0.00 THEN
        INSERT INTO payment (
            code,
            reservation_id,
            amount,
            method,
            status,
            notes,
            received_by
        ) VALUES (
            'PAY-RSV-' || TO_CHAR(CURRENT_TIMESTAMP, 'YYYYMMDD') || '-' || UPPER(SUBSTR(MD5(RANDOM()::TEXT || CLOCK_TIMESTAMP()::TEXT), 1, 6)),
            v_reservation_id,
            v_deposit_amount,
            'VIETQR',
            'UNPAID',
            format('Tiền cọc giữ chỗ đỗ xe %s (%s)', v_slot.code, v_code),
            p_created_by
        );
    END IF;

    RETURN v_reservation_id;
END;
$$;

COMMENT ON FUNCTION fn_create_booking(BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, VARCHAR, VARCHAR, VARCHAR, TEXT, BIGINT) IS 'Tạo yêu cầu đặt chỗ trước, kiểm tra khung thời gian chính sách, độ phù hợp loại xe, danh sách đen, ràng buộc chống trùng lặp và tạo chứng từ tiền cọc.';

-- -----------------------------------------------------------------------------
-- 11.4. Hàm: fn_cancel_booking()
-- Huỷ lượt đặt chỗ đang hoạt động, thực thi thời hạn huỷ, hoàn tiền cọc hoặc tịch thu cọc theo chính sách.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_cancel_booking(
    p_reservation_id BIGINT,
    p_cancelled_by BIGINT,
    p_cancel_reason TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_rsv RECORD;
    v_policy RECORD;
    v_refund_eligible BOOLEAN := FALSE;
    v_deadline TIMESTAMPTZ;
    v_refund_amount NUMERIC(12, 2) := 0.00;
BEGIN
    SELECT r.*, pf.lot_id
    INTO v_rsv
    FROM slot_reservation r
    JOIN parking_slot ps ON ps.id = r.slot_id
    JOIN parking_zone pz ON pz.id = ps.zone_id
    JOIN parking_floor pf ON pf.id = pz.floor_id
    WHERE r.id = p_reservation_id AND r.deleted_at IS NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Lịch đặt chỗ (ID: %) không tồn tại hoặc đã bị xóa.', p_reservation_id
            USING ERRCODE = 'check_violation';
    END IF;

    IF v_rsv.status NOT IN ('PENDING_PAYMENT', 'CONFIRMED') THEN
        RAISE EXCEPTION 'Không thể hủy đặt chỗ ở trạng thái hiện tại (%).', v_rsv.status
            USING ERRCODE = 'check_violation',
                  HINT = 'Only PENDING_PAYMENT or CONFIRMED reservations may be cancelled (PROP-BOOK-CANCEL-INVALID-STATUS).';
    END IF;

    -- Lấy chính sách đặt chỗ để tính thời hạn hoàn tiền cọc
    SELECT * INTO v_policy
    FROM booking_policy
    WHERE lot_id = v_rsv.lot_id AND deleted_at IS NULL AND is_active = TRUE;

    IF NOT FOUND THEN
        v_policy.cancel_free_before_minutes := 60;
    END IF;

    IF v_rsv.status = 'PENDING_PAYMENT' THEN
        -- Huỷ chứng từ tiền cọc chưa thanh toán nếu có
        UPDATE payment
        SET status = 'CANCELLED',
            notes = COALESCE(notes || '; ', '') || 'Cancelled upon reservation cancellation.'
        WHERE reservation_id = p_reservation_id
          AND status = 'UNPAID'
          AND deleted_at IS NULL;
    ELSIF v_rsv.status = 'CONFIRMED' THEN
        v_deadline := v_rsv.reserved_from - (v_policy.cancel_free_before_minutes * INTERVAL '1 minute');
        IF CURRENT_TIMESTAMP <= v_deadline THEN
            v_refund_eligible := TRUE;
            v_refund_amount := v_rsv.deposit_amount;
            -- Hoàn tiền cọc đã thanh toán
            UPDATE payment
            SET status = 'REFUNDED',
                notes = COALESCE(notes || '; ', '') || format('Hoàn cọc hủy trước deadline (%s phút).', v_policy.cancel_free_before_minutes)
            WHERE reservation_id = p_reservation_id
              AND status = 'PAID'
              AND deleted_at IS NULL;
        ELSE
            v_refund_eligible := FALSE;
            v_refund_amount := 0.00;
            -- Tịch thu tiền cọc do huỷ sát giờ quá thời hạn cho phép
            UPDATE payment
            SET notes = COALESCE(notes || '; ', '') || format('Tịch thu cọc: Hủy sau deadline (%s phút trước giờ đặt).', v_policy.cancel_free_before_minutes)
            WHERE reservation_id = p_reservation_id
              AND status = 'PAID'
              AND deleted_at IS NULL;
        END IF;
    END IF;

    -- Cập nhật trạng thái đặt chỗ sang CANCELLED
    UPDATE slot_reservation
    SET status = 'CANCELLED',
        cancelled_at = CURRENT_TIMESTAMP,
        cancelled_by = p_cancelled_by,
        cancel_reason = p_cancel_reason,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_reservation_id;

    RETURN jsonb_build_object(
        'reservation_id', p_reservation_id,
        'status', 'CANCELLED',
        'refund_eligible', v_refund_eligible,
        'refund_amount', v_refund_amount,
        'cancelled_at', CURRENT_TIMESTAMP
    );
END;
$$;

COMMENT ON FUNCTION fn_cancel_booking(BIGINT, BIGINT, TEXT) IS 'Huỷ lượt đặt chỗ đang hoạt động, thực thi hạn chót huỷ đặt chỗ, hoàn trả tiền cọc hoặc tịch thu cọc.';

-- -----------------------------------------------------------------------------
-- 11.5. Hàm: fn_expire_stale_bookings()
-- Hàm định kỳ chuyển các đặt chỗ quá hạn giữ cọc sang EXPIRED và quá thời gian ân hạn
-- sang NO_SHOW với khả năng thực thi lặp lại an toàn (lũy đẳng).
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_expire_stale_bookings()
RETURNS INTEGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_expired_count INTEGER := 0;
    v_no_show_count INTEGER := 0;
    v_rec RECORD;
BEGIN
    -- 1. Chuyển sang EXPIRED các đặt chỗ PENDING_PAYMENT đã quá hạn giữ chỗ
    FOR v_rec IN
        SELECT r.id
        FROM slot_reservation r
        WHERE r.status = 'PENDING_PAYMENT'
          AND r.deleted_at IS NULL
          AND r.hold_expires_at IS NOT NULL
          AND CURRENT_TIMESTAMP > r.hold_expires_at
        FOR UPDATE OF r
    LOOP
        UPDATE slot_reservation
        SET status = 'EXPIRED',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_rec.id;

        -- Huỷ các chứng từ thanh toán tiền cọc chưa thanh toán
        UPDATE payment
        SET status = 'CANCELLED',
            notes = COALESCE(notes || '; ', '') || 'Cancelled due to booking hold expiration.'
        WHERE reservation_id = v_rec.id
          AND status = 'UNPAID'
          AND deleted_at IS NULL;

        v_expired_count := v_expired_count + 1;
    END LOOP;

    -- 2. Đánh dấu NO_SHOW các đặt chỗ CONFIRMED nếu quá thời gian bắt đầu cộng thời gian ân hạn mà xe chưa vào
    FOR v_rec IN
        SELECT r.id, r.reserved_from, COALESCE(bp.grace_minutes, 15) AS grace_minutes
        FROM slot_reservation r
        JOIN parking_slot ps ON ps.id = r.slot_id
        JOIN parking_zone pz ON pz.id = ps.zone_id
        JOIN parking_floor pf ON pf.id = pz.floor_id
        LEFT JOIN booking_policy bp ON bp.lot_id = pf.lot_id AND bp.deleted_at IS NULL AND bp.is_active = TRUE
        WHERE r.status = 'CONFIRMED'
          AND r.deleted_at IS NULL
          AND CURRENT_TIMESTAMP > (r.reserved_from + (COALESCE(bp.grace_minutes, 15) * INTERVAL '1 minute'))
          AND NOT EXISTS (
              SELECT 1 FROM vehicle_entry_exit_log l
              WHERE l.reservation_id = r.id
          )
        FOR UPDATE OF r
    LOOP
        UPDATE slot_reservation
        SET status = 'NO_SHOW',
            no_show_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_rec.id;

        -- Tiền cọc đã thanh toán bị tịch thu (giữ nguyên PAID) kèm ghi chú kiểm toán
        UPDATE payment
        SET notes = COALESCE(notes || '; ', '') || 'Tiền cọc bị tịch thu do khách không đến nhận chỗ (NO_SHOW).'
        WHERE reservation_id = v_rec.id
          AND status = 'PAID'
          AND deleted_at IS NULL;

        v_no_show_count := v_no_show_count + 1;
    END LOOP;

    RETURN v_expired_count + v_no_show_count;
END;
$$;

COMMENT ON FUNCTION fn_expire_stale_bookings() IS 'Hàm quét định kỳ chuyển đặt chỗ giữ cọc quá hạn sang EXPIRED và đặt chỗ quá hạn nhận chỗ sang NO_SHOW với khả năng thực thi lặp lại an toàn (lũy đẳng).';

COMMIT;
