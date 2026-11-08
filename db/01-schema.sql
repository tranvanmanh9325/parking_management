-- Lược đồ cơ sở dữ liệu hệ thống quản lý bãi đỗ xe ô tô (parking_management).
-- File tạo 29 bảng, 9 view thống kê và 5 hàm trigger tự động (T1 - T5).
--
-- Quy ước chung trong toàn bộ hệ thống:
-- 1. Xoá mềm: các bảng nghiệp vụ dùng deleted_at và deleted_by; cấm xoá cứng dữ liệu.
-- 2. Khoá lạc quan: dùng cột row_version tự tăng khi cập nhật để chống ghi đè đồng thời.
-- 3. Khoá ngoại: 100% khoá ngoại dùng ON DELETE RESTRICT để tránh xoá nhầm dữ liệu.
-- 4. Script chỉ tạo mới (create-only), không chứa lệnh DROP hay TRUNCATE.
--
-- Các cột chuẩn (id, created_at, updated_at, row_version, deleted_at, deleted_by)
-- được áp dụng nhất quán và không lặp lại chú thích ở từng cột.
-- Cách chạy: psql -U parking_user -d parking_db -v ON_ERROR_STOP=1 -f db/01-schema.sql

BEGIN;

SET client_encoding = 'UTF8';

-- Cần cho ràng buộc loại trừ theo thời gian (EXCLUDE USING gist)
CREATE EXTENSION btree_gist;

-- Cần cho chỉ mục GIN trigram tìm kiếm chuỗi con nhanh
CREATE EXTENSION IF NOT EXISTS pg_trgm;


-- 1. Xác thực và phân quyền

-- 1.1. Bảng account
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

COMMENT ON TABLE account IS 'Tài khoản người dùng đăng nhập bằng email hoặc số điện thoại, phân quyền theo vai trò.';
COMMENT ON COLUMN account.role IS 'Vai trò phân quyền: MANAGER (quản lý), EMPLOYEE (nhân viên), CUSTOMER (khách).';
COMMENT ON COLUMN account.is_active IS 'Cờ trạng thái tài khoản: TRUE là hoạt động, FALSE là bị tạm khoá.';

-- 1.2. Bảng persistent_login_token
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

COMMENT ON TABLE persistent_login_token IS 'Lưu token ghi nhớ đăng nhập trình duyệt (Remember Me), chỉ lưu giá trị băm an toàn.';

-- 1.3. Bảng password_reset_token
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

COMMENT ON TABLE password_reset_token IS 'Token một lần phục vụ đặt lại mật khẩu khi người dùng quên thông tin đăng nhập.';


-- 2. Nhân sự và địa giới hành chính

-- 2.1. Bảng position
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

COMMENT ON TABLE position IS 'Danh mục chức vụ nội bộ của nhân viên như quản lý, thu ngân, kỹ thuật viên.';

-- 2.2. Bảng administrative_province
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

COMMENT ON TABLE administrative_province IS 'Bảng tỉnh và thành phố trực thuộc trung ương theo danh mục hành chính chuẩn.';

-- 2.3. Bảng administrative_district
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

COMMENT ON TABLE administrative_district IS 'Quận huyện trực thuộc từng tỉnh thành, hỗ trợ chuẩn hoá địa chỉ người dùng.';

-- 2.4. Bảng administrative_ward
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

COMMENT ON TABLE administrative_ward IS 'Phường xã thuộc quận huyện, cấp hành chính chi tiết nhất của địa chỉ.';

-- 2.5. Bảng employee
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

COMMENT ON TABLE employee IS 'Hồ sơ nhân viên vận hành bãi xe, liên kết với chức vụ và tài khoản đăng nhập.';
COMMENT ON COLUMN employee.gender IS 'Giới tính nhân viên: Nam hoặc Nữ.';
COMMENT ON COLUMN employee.status IS 'Trạng thái làm việc của nhân viên: ACTIVE hoặc INACTIVE.';


-- 3. Khách hàng, danh sách đen và xe

-- 3.1. Bảng customer
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

CREATE INDEX idx_customer_full_name_trgm ON customer USING gin (full_name gin_trgm_ops) WHERE deleted_at IS NULL;

CREATE INDEX idx_customer_phone_trgm ON customer USING gin (phone gin_trgm_ops) WHERE deleted_at IS NULL;

CREATE INDEX idx_customer_idcard_trgm ON customer USING gin (identity_card_number gin_trgm_ops) WHERE deleted_at IS NULL;

COMMENT ON TABLE customer IS 'Thông tin khách gửi xe, hỗ trợ cả khách đăng ký tài khoản lẫn khách vãng lai.';
COMMENT ON COLUMN customer.gender IS 'Giới tính khách hàng: Nam hoặc Nữ.';
COMMENT ON COLUMN customer.is_anonymized IS 'Đánh dấu dữ liệu cá nhân đã được ẩn danh theo yêu cầu quyền riêng tư.';
COMMENT ON COLUMN customer.anonymized_at IS 'Thời điểm thực hiện ẩn danh thông tin cá nhân của khách hàng.';
COMMENT ON COLUMN customer.status IS 'Tình trạng khách: ACTIVE (hoạt động), SUSPENDED (tạm dừng), BLACKLISTED (chặn).';
COMMENT ON COLUMN customer.status_reason IS 'Nguyên nhân chi tiết dẫn đến việc tạm dừng phục vụ hoặc chặn khách hàng.';
COMMENT ON COLUMN customer.identity_card_number IS 'Số thẻ căn cước công dân hoặc chứng minh nhân dân của khách hàng.';
COMMENT ON COLUMN customer.address IS 'Địa chỉ thường trú hoặc nơi liên hệ gửi thư từ của khách hàng.';

-- 3.2. Bảng plate_blacklist
CREATE TABLE plate_blacklist (
    id BIGSERIAL,
    license_plate VARCHAR(20) NOT NULL,
    license_plate_norm VARCHAR(20) GENERATED ALWAYS AS (UPPER(REGEXP_REPLACE(license_plate, '[^A-Za-z0-9]', '', 'g'))) STORED,
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

COMMENT ON TABLE plate_blacklist IS 'Danh sách biển số xe bị chặn vào bãi kèm lý do vi phạm hoặc cảnh báo an ninh.';
COMMENT ON COLUMN plate_blacklist.license_plate_norm IS 'Biển số chuẩn hoá không dấu cách và gạch nối (vd 51A12345).';
COMMENT ON COLUMN plate_blacklist.reason IS 'Căn cứ đưa xe vào danh sách chặn (như trộm cắp, gây rối, nợ cước phí).';
COMMENT ON COLUMN plate_blacklist.unpaid_amount IS 'Tổng số tiền cước hoặc tiền bồi thường còn nợ chưa trả, đơn vị VNĐ.';
COMMENT ON COLUMN plate_blacklist.is_active IS 'Tình trạng chặn: TRUE là đang chặn vào bãi, FALSE là đã gỡ chặn.';
COMMENT ON COLUMN plate_blacklist.added_by IS 'Người lập biên bản đưa xe vào danh sách chặn (FK tham chiếu employee).';

-- 3.3. Bảng vehicle_type
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

COMMENT ON TABLE vehicle_type IS 'Phân loại phương tiện như ô tô con, xe tải nhỏ, xe điện để áp mức giá và xếp chỗ.';

-- 3.4. Bảng ticket_type
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

COMMENT ON TABLE ticket_type IS 'Gói vé tháng hoặc vé định kỳ theo loại xe, quy định giá tiền và chu kỳ sử dụng.';
COMMENT ON COLUMN ticket_type.default_price IS 'Mức giá niêm yết chuẩn của gói vé, đơn vị VNĐ.';
COMMENT ON COLUMN ticket_type.duration_days IS 'Số ngày hiệu lực của gói vé định kỳ, thường là 30 ngày.';

-- 3.5. Bảng vehicle
CREATE TABLE vehicle (
    id BIGSERIAL,
    code VARCHAR(10) NOT NULL,
    license_plate VARCHAR(20) NOT NULL,
    license_plate_norm VARCHAR(20) GENERATED ALWAYS AS (UPPER(REGEXP_REPLACE(license_plate, '[^A-Za-z0-9]', '', 'g'))) STORED,
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

COMMENT ON TABLE vehicle IS 'Xe thuộc sở hữu của khách hàng, có biển số chuẩn hoá phục vụ đối soát camera.';
COMMENT ON COLUMN vehicle.license_plate_norm IS 'Biển số xe chuẩn hoá không ký tự đặc biệt, dùng so khớp nhanh.';
COMMENT ON COLUMN vehicle.ticket_type_id IS 'Gói vé tháng đang áp dụng cho xe; ứng dụng cập nhật khi cấp hoặc gia hạn vé.';
COMMENT ON COLUMN vehicle.ticket_expires_at IS 'Ngày hết hạn vé tháng hiện hành; ứng dụng cập nhật cùng lúc với ticket_type_id.';
COMMENT ON COLUMN vehicle.image_url IS 'Ảnh chụp xe phục vụ nhận diện trực quan và đối soát.';
COMMENT ON COLUMN vehicle.brand IS 'Hãng sản xuất phương tiện (ví dụ Toyota, Honda, VinFast).';
COMMENT ON COLUMN vehicle.color IS 'Màu sơn thực tế của phương tiện theo đăng ký hoặc quan sát.';


-- 4. Cấu trúc bãi đỗ, ô đỗ và đặt chỗ

-- 4.1. Bảng parking_lot
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

COMMENT ON TABLE parking_lot IS 'Thông tin bãi đỗ xe gồm tên, địa chỉ, sức chứa và toạ độ định vị trên bản đồ.';

-- 4.2. Bảng booking_policy
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

COMMENT ON TABLE booking_policy IS 'Chính sách đặt chỗ trước: thời gian giữ chỗ, số tiền cọc và quy định huỷ lượt.';
COMMENT ON COLUMN booking_policy.deposit_amount IS 'Tiền cọc cần nộp khi đặt giữ chỗ trước, đơn vị VNĐ.';
COMMENT ON COLUMN booking_policy.hold_minutes IS 'Số phút giữ chỗ chờ khách trả cọc; quá hạn thì đặt chỗ coi như hết hạn.';
COMMENT ON COLUMN booking_policy.grace_minutes IS 'Số phút ân hạn cho khách đến muộn so với giờ hẹn; quá mức này coi là NO_SHOW.';
COMMENT ON COLUMN booking_policy.early_checkin_minutes IS 'Số phút tối đa cho phép khách vào bãi trước thời điểm bắt đầu hẹn giữ chỗ.';
COMMENT ON COLUMN booking_policy.cancel_free_before_minutes IS 'Khoảng thời gian tối thiểu huỷ trước giờ hẹn để được nhận lại 100% tiền cọc.';
COMMENT ON COLUMN booking_policy.max_advance_days IS 'Số ngày tối đa cho phép khách tạo lịch hẹn đặt chỗ trước tính từ hiện tại.';
COMMENT ON COLUMN booking_policy.min_duration_minutes IS 'Thời lượng gửi xe ngắn nhất cho một lượt đặt trước, tính theo phút.';
COMMENT ON COLUMN booking_policy.max_duration_minutes IS 'Thời lượng gửi xe dài nhất cho một lượt đặt trước, tính theo phút.';
COMMENT ON COLUMN booking_policy.is_active IS 'Hiệu lực áp dụng: TRUE là chính sách đang vận hành, FALSE là tạm ngưng.';

-- 4.3. Bảng parking_floor
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

COMMENT ON TABLE parking_floor IS 'Các tầng trong bãi xe, hỗ trợ phân chia khu vực đỗ và vẽ sơ đồ mặt bằng.';

-- 4.4. Bảng parking_zone
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

COMMENT ON TABLE parking_zone IS 'Khu vực đỗ xe trong từng tầng, dùng nhóm các ô có cùng đặc tính hoặc loại xe.';

-- 4.5. Bảng parking_slot
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

COMMENT ON TABLE parking_slot IS 'Vị trí ô đỗ cụ thể: AVAILABLE (trống), RESERVED (đã đặt), OCCUPIED (có xe).';
COMMENT ON COLUMN parking_slot.status IS 'Trạng thái ô: AVAILABLE (trống), RESERVED (đã đặt), OCCUPIED (có xe), CHARGING (đang sạc), MAINTENANCE (bảo trì).';
COMMENT ON COLUMN parking_slot.slot_kind IS 'Loại ô đỗ: STANDARD (tiêu chuẩn), PRIORITY (ưu tiên) hoặc EV_CHARGING (sạc điện).';
COMMENT ON COLUMN parking_slot.map_row IS 'Chỉ số hàng của ô đỗ trên lưới sơ đồ mặt bằng.';
COMMENT ON COLUMN parking_slot.map_col IS 'Chỉ số cột của ô đỗ trên lưới sơ đồ mặt bằng.';
COMMENT ON COLUMN parking_slot.length IS 'Chiều dài ô, đơn vị mét.';
COMMENT ON COLUMN parking_slot.width IS 'Chiều rộng ô, đơn vị mét.';
COMMENT ON COLUMN parking_slot.height IS 'Chiều cao thông thuỷ trần xe tối đa, đơn vị mét.';

-- 4.6. Bảng slot_allowed_vehicle_type
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

COMMENT ON TABLE slot_allowed_vehicle_type IS 'Bảng phụ quy định mỗi ô đỗ cho phép những loại phương tiện nào vào gửi.';

-- 4.7. Bảng slot_reservation
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

COMMENT ON TABLE slot_reservation IS 'Lượt khách đặt giữ chỗ trước theo khung giờ, có ràng buộc chống trùng chỗ.';
COMMENT ON COLUMN slot_reservation.status IS 'Vòng đời đặt chỗ: PENDING_PAYMENT, CONFIRMED, CHECKED_IN, COMPLETED, CANCELLED, EXPIRED, NO_SHOW.';
COMMENT ON COLUMN slot_reservation.reserved_from IS 'Mốc giờ bắt đầu giữ chỗ theo lịch hẹn khách đã đăng ký.';
COMMENT ON COLUMN slot_reservation.reserved_until IS 'Giờ kết thúc thời gian giữ chỗ theo lịch hẹn khách đăng ký.';
COMMENT ON COLUMN slot_reservation.hold_expires_at IS 'Hạn chót thanh toán cọc; quá mốc này ứng dụng chuyển lượt đặt sang EXPIRED.';
COMMENT ON COLUMN slot_reservation.deposit_amount IS 'Mức tiền cọc cần thanh toán để giữ ô đỗ, đơn vị VNĐ.';
COMMENT ON COLUMN slot_reservation.booking_channel IS 'Kênh đặt chỗ: CUSTOMER_PORTAL (cổng khách hàng) hoặc STAFF (nhân viên đặt hộ).';
COMMENT ON COLUMN slot_reservation.reserved_name IS 'Tên người liên hệ nhận chỗ đối với khách vãng lai chưa có hồ sơ.';
COMMENT ON COLUMN slot_reservation.reserved_phone IS 'Số điện thoại liên hệ nhận chỗ của khách vãng lai đặt trước.';
COMMENT ON COLUMN slot_reservation.checked_in_at IS 'Lúc khách thực sự vào bãi nhận chỗ.';
COMMENT ON COLUMN slot_reservation.completed_at IS 'Lúc khách trả ô đỗ, thanh toán xong và rời khỏi bãi xe.';
COMMENT ON COLUMN slot_reservation.cancelled_at IS 'Thời điểm lượt đặt chỗ bị huỷ bởi khách hàng hoặc nhân viên quầy.';
COMMENT ON COLUMN slot_reservation.cancelled_by IS 'Tài khoản thực hiện huỷ lượt đặt chỗ (FK tham chiếu account).';
COMMENT ON COLUMN slot_reservation.cancel_reason IS 'Lý do huỷ lượt đặt giữ chỗ từ phía khách hoặc ban quản lý.';
COMMENT ON COLUMN slot_reservation.no_show_at IS 'Mốc thời gian ghi nhận khách vắng mặt quá hạn sau khoảng ân hạn.';
COMMENT ON COLUMN slot_reservation.created_by IS 'Nhân viên lập đơn đặt giữ chỗ (FK tham chiếu employee).';


-- 5. Vé và gia hạn

-- 5.1. Bảng ticket
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

COMMENT ON TABLE ticket IS 'Vé tháng: một xe giữ một ô cố định trong khoảng thời gian đã mua.';
COMMENT ON COLUMN ticket.status IS 'Trạng thái vé tháng: ACTIVE (còn hạn), EXPIRED (hết hạn), CANCELLED (huỷ), RENEWING (đang gia hạn).';
COMMENT ON COLUMN ticket.effective_from IS 'Ngày bắt đầu có giá trị sử dụng của vé tháng.';
COMMENT ON COLUMN ticket.effective_to IS 'Hạn dùng cuối của vé tháng; quá mốc này ứng dụng chuyển vé sang EXPIRED.';
COMMENT ON COLUMN ticket.price IS 'Giá tiền thực tế thu khi phát hành vé tháng, đơn vị VNĐ.';
COMMENT ON COLUMN ticket.issued_by IS 'Người thực hiện cấp phát vé tháng (FK tham chiếu employee).';

-- 5.2. Bảng ticket_renewal
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

COMMENT ON TABLE ticket_renewal IS 'Lịch sử các lần gia hạn vé tháng kèm thông tin chênh lệch phí và thời hạn mới.';
COMMENT ON COLUMN ticket_renewal.old_slot_id IS 'Ô đỗ chỉ định trước khi gia hạn (FK tham chiếu parking_slot).';
COMMENT ON COLUMN ticket_renewal.new_slot_id IS 'Ô đỗ chỉ định áp dụng cho chu kỳ mới (FK tham chiếu parking_slot).';
COMMENT ON COLUMN ticket_renewal.old_ticket_type_id IS 'Loại vé cũ đang sử dụng trước khi gia hạn (FK tham chiếu ticket_type).';
COMMENT ON COLUMN ticket_renewal.new_ticket_type_id IS 'Loại vé mới chọn cho chu kỳ kế tiếp (FK tham chiếu ticket_type).';
COMMENT ON COLUMN ticket_renewal.old_price IS 'Mức giá vé của kỳ sử dụng trước, đơn vị VNĐ.';
COMMENT ON COLUMN ticket_renewal.new_price IS 'Mức giá vé áp dụng cho kỳ mới, đơn vị VNĐ.';
COMMENT ON COLUMN ticket_renewal.old_effective_to IS 'Hạn dùng cũ của vé trước khi thực hiện gia hạn.';
COMMENT ON COLUMN ticket_renewal.new_effective_to IS 'Hạn dùng mới của vé sau khi gia hạn thành công.';
COMMENT ON COLUMN ticket_renewal.additional_price IS 'Khoản phụ phí chênh lệch phát sinh khi nâng gói vé hoặc đổi ô đỗ, đơn vị VNĐ.';
COMMENT ON COLUMN ticket_renewal.renewed_by IS 'Người ghi nhận giao dịch gia hạn vé (FK tham chiếu employee).';


-- 6. Cổng, phiên ra vào và thanh toán

-- 6.1. Bảng parking_gate
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

COMMENT ON TABLE parking_gate IS 'Cổng kiểm soát ra vào gắn barrier và camera nhận diện biển số tự động.';
COMMENT ON COLUMN parking_gate.direction IS 'Chiều lưu thông của cổng: IN (cổng xe vào), OUT (cổng xe ra).';
COMMENT ON COLUMN parking_gate.camera_status IS 'Tình trạng camera: ONLINE (tốt), LOW_LIGHT (thiếu sáng), DEGRADED (kém), OFFLINE (mất kết nối).';
COMMENT ON COLUMN parking_gate.is_active IS 'Tình trạng mở cổng: TRUE là sẵn sàng tiếp nhận xe, FALSE là đóng cổng.';
COMMENT ON COLUMN parking_gate.is_auto_scan IS 'Camera AI tự quét biển số (TRUE) hay nhân viên quét thủ công (FALSE).';

-- 6.2. Bảng vehicle_entry_exit_log
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
    license_plate_norm VARCHAR(20) GENERATED ALWAYS AS (UPPER(REGEXP_REPLACE(license_plate, '[^A-Za-z0-9]', '', 'g'))) STORED,
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

COMMENT ON TABLE vehicle_entry_exit_log IS 'Nhật ký lượt xe ra vào bãi, lưu biển số, thời gian, ảnh chụp và cước phí.';
COMMENT ON COLUMN vehicle_entry_exit_log.license_plate_norm IS 'Biển số xe nhận dạng đã chuẩn hoá, dùng tìm kiếm và đối soát.';
COMMENT ON COLUMN vehicle_entry_exit_log.recognition_source IS 'Phương thức ghi nhận biển số: AI (camera tự đọc) hoặc MANUAL (nhân viên nhập tay).';
COMMENT ON COLUMN vehicle_entry_exit_log.review_status IS 'Kiểm duyệt nhận diện: AUTO, MATCHED, NEEDS_REVIEW, APPROVED, REJECTED.';
COMMENT ON COLUMN vehicle_entry_exit_log.session_code IS 'Mã phiên gửi xe duy nhất theo định dạng chuẩn (ví dụ #PK-20261108-000001).';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_time IS 'Giờ xe lăn bánh qua barrier cổng vào.';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_time IS 'Lúc xe rời khỏi cổng ra; để trống nếu xe đang đỗ trong bãi.';
COMMENT ON COLUMN vehicle_entry_exit_log.fee_amount IS 'Phí trông giữ thực thu cho lượt gửi xe, đơn vị VNĐ.';
COMMENT ON COLUMN vehicle_entry_exit_log.ai_confidence IS 'Độ tin cậy nhận diện biển số của camera AI, thang điểm từ 0 đến 100.';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_image_url IS 'Đường dẫn ảnh chụp biển số và đầu xe tại cổng vào.';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_image_url IS 'Đường dẫn ảnh chụp biển số và đầu xe tại cổng ra.';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_handled_by IS 'Nhân viên trực cổng hỗ trợ xe vào (FK tham chiếu employee).';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_handled_by IS 'Nhân viên trực cổng tính tiền và cho xe ra (FK tham chiếu employee).';
COMMENT ON COLUMN vehicle_entry_exit_log.entry_gate_id IS 'Cổng kiểm soát nơi xe đi vào bãi (FK tham chiếu parking_gate).';
COMMENT ON COLUMN vehicle_entry_exit_log.exit_gate_id IS 'Cổng kiểm soát nơi xe đi ra khỏi bãi (FK tham chiếu parking_gate).';
COMMENT ON COLUMN vehicle_entry_exit_log.reservation_id IS 'Lượt đặt trước gắn với phiên gửi xe này (FK tham chiếu slot_reservation).';
COMMENT ON COLUMN vehicle_entry_exit_log.ticket_id IS 'Vé tháng đang áp dụng cho lượt gửi xe này (FK tham chiếu ticket).';

-- 6.3. Bảng payment
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

COMMENT ON TABLE payment IS 'Chứng từ giao dịch thanh toán vé, lượt gửi hoặc tiền cọc qua tiền mặt/VietQR.';
COMMENT ON COLUMN payment.method IS 'Hình thức thanh toán: CASH (tiền mặt) hoặc VIETQR (quét mã chuyển khoản ngân hàng).';
COMMENT ON COLUMN payment.status IS 'Trạng thái giao dịch: UNPAID (chờ), PAID (đã trả), CANCELLED (huỷ), REFUNDED (hoàn tiền).';
COMMENT ON COLUMN payment.amount IS 'Số tiền thanh toán thực tế của giao dịch, đơn vị VNĐ.';
COMMENT ON COLUMN payment.paid_at IS 'Lúc tiền về tài khoản hoặc nhân viên nhận đủ tiền mặt.';
COMMENT ON COLUMN payment.provider_ref IS 'Mã giao dịch đối soát từ ngân hàng hoặc đơn vị cung cấp VietQR.';
COMMENT ON COLUMN payment.received_by IS 'Thu ngân tiếp nhận tiền mặt tại quầy (FK tham chiếu employee).';
COMMENT ON COLUMN payment.reservation_id IS 'Đơn đặt chỗ (FK tham chiếu slot_reservation); dùng thanh toán tiền cọc giữ ô.';
COMMENT ON COLUMN payment.ticket_id IS 'Vé tháng (FK tham chiếu ticket); dùng thanh toán tiền mua vé mới.';
COMMENT ON COLUMN payment.renewal_id IS 'Đợt gia hạn (FK tham chiếu ticket_renewal); dùng thanh toán phí gia hạn vé.';
COMMENT ON COLUMN payment.session_id IS 'Lượt gửi xe (FK tham chiếu vehicle_entry_exit_log); dùng thanh toán cước vãng lai.';


-- 7. Nhật ký hoạt động, cảnh báo, tin tức và thông báo

-- 7.1. Bảng activity_log
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

COMMENT ON TABLE activity_log IS 'Nhật ký ghi vết thao tác dữ liệu dạng append-only phục vụ tra cứu và kiểm toán.';

-- 7.2. Bảng system_alert
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

COMMENT ON TABLE system_alert IS 'Cảnh báo an ninh và kỹ thuật tự động như phát hiện xe danh sách đen hoặc quá giờ.';
COMMENT ON COLUMN system_alert.alert_type IS 'Phân loại cảnh báo: BLACKLIST_PLATE, OVERSTAY, CAMERA_QUALITY hoặc SYSTEM.';
COMMENT ON COLUMN system_alert.severity IS 'Mức độ nghiêm trọng của cảnh báo: INFO (thông tin), WARNING (chú ý), CRITICAL (khẩn cấp).';

-- 7.3. Bảng news
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

COMMENT ON TABLE news IS 'Tin tức và thông báo hiển thị cho khách hàng trên cổng thông tin trực tuyến.';

-- 7.4. Bảng notification
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

COMMENT ON TABLE notification IS 'Thông báo gửi đến từng người dùng về hạn vé, thanh toán hoặc nhắc nhở xe vào ra.';
COMMENT ON COLUMN notification.notification_type IS 'Phân loại tin báo: SYSTEM (vận hành), TICKET_EXPIRY (hạn vé), PAYMENT (thanh toán), SECURITY (an ninh).';

-- 8. Các trigger tự động (T1 - T5)

-- T1. set_row_version_and_updated_at: tự động tăng phiên bản và cập nhật thời gian
CREATE FUNCTION set_row_version_and_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    NEW.row_version := OLD.row_version + 1;
    -- Hai bảng ticket_renewal và vehicle_entry_exit_log không có cột updated_at
    IF TG_TABLE_NAME NOT IN ('ticket_renewal', 'vehicle_entry_exit_log') THEN
        NEW.updated_at := CURRENT_TIMESTAMP;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION set_row_version_and_updated_at() IS 'Tự động tăng row_version thêm 1 và gán updated_at bằng thời điểm hiện tại khi cập nhật.';

-- T2. block_hard_delete: chặn xoá cứng trên các bảng xoá mềm
CREATE FUNCTION block_hard_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Không được xoá hẳn dòng dữ liệu. Vui lòng đặt giá trị cho deleted_at để xoá mềm.'
        USING ERRCODE = 'check_violation';
END;
$$;

COMMENT ON FUNCTION block_hard_delete() IS 'Chặn thao tác xoá cứng dòng dữ liệu, nhắc nhở dùng cột deleted_at để xoá mềm.';

-- T3. block_activity_log_mutation: nhật ký hoạt động là bảng chỉ ghi (append-only)
CREATE FUNCTION block_activity_log_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'Bảng activity_log chỉ cho phép thêm mới, không được sửa hoặc xoá.'
        USING ERRCODE = 'check_violation';
END;
$$;

COMMENT ON FUNCTION block_activity_log_mutation() IS 'Chặn thao tác UPDATE và DELETE trên activity_log, chỉ cho phép chèn dòng mới.';

-- T4. sync_reservation_on_payment: cập nhật đặt chỗ khi hoàn tất cọc
CREATE FUNCTION sync_reservation_on_payment()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Khi thanh toán chuyển sang PAID, tự động chuyển đặt chỗ sang CONFIRMED
    IF NEW.reservation_id IS NOT NULL AND NEW.status = 'PAID' AND
       (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'PAID') THEN
        UPDATE slot_reservation
        SET status = 'CONFIRMED'
        WHERE id = NEW.reservation_id
          AND status = 'PENDING_PAYMENT'
          AND deleted_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION sync_reservation_on_payment() IS 'Tự động chuyển trạng thái đặt chỗ sang CONFIRMED khi nhận thanh toán cọc thành công.';

-- T5. sync_slot_status_on_traffic: đồng bộ trạng thái ô đỗ theo lượt xe ra vào
CREATE FUNCTION sync_slot_status_on_traffic()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Xe vào hoặc chuyển ô trong bãi (chưa ra)
    IF NEW.exit_time IS NULL THEN
        -- Nhận ô mới nếu vừa vào hoặc vừa đổi ô
        IF NEW.slot_id IS NOT NULL AND
           (TG_OP = 'INSERT' OR OLD.exit_time IS NOT NULL OR OLD.slot_id IS DISTINCT FROM NEW.slot_id) THEN
            UPDATE parking_slot
            SET status = 'OCCUPIED'
            WHERE id = NEW.slot_id
              AND status <> 'MAINTENANCE';
        END IF;

        -- Trả lại ô cũ nếu đổi sang ô khác hoặc bỏ gán ô
        IF TG_OP = 'UPDATE' AND OLD.slot_id IS NOT NULL AND OLD.slot_id IS DISTINCT FROM NEW.slot_id THEN
            UPDATE parking_slot
            SET status = 'AVAILABLE'
            WHERE id = OLD.slot_id
              AND status <> 'MAINTENANCE';
        END IF;

    -- Xe ra: giải phóng ô khi phiên đỗ kết thúc
    ELSIF TG_OP = 'UPDATE' AND OLD.exit_time IS NULL AND NEW.exit_time IS NOT NULL THEN
        UPDATE parking_slot
        SET status = 'AVAILABLE'
        WHERE (id = NEW.slot_id OR id = OLD.slot_id)
          AND status <> 'MAINTENANCE';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION sync_slot_status_on_traffic() IS 'Cập nhật trạng thái ô đỗ thành OCCUPIED khi xe vào và AVAILABLE khi xe ra bãi.';

-- Gắn trigger T1 (set_row_version_and_updated_at) cho 20 bảng có row_version
CREATE TRIGGER trg_account_row_version BEFORE UPDATE ON account FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_position_row_version BEFORE UPDATE ON position FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_employee_row_version BEFORE UPDATE ON employee FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_customer_row_version BEFORE UPDATE ON customer FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_plate_blacklist_row_version BEFORE UPDATE ON plate_blacklist FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_vehicle_type_row_version BEFORE UPDATE ON vehicle_type FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_ticket_type_row_version BEFORE UPDATE ON ticket_type FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_vehicle_row_version BEFORE UPDATE ON vehicle FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_parking_lot_row_version BEFORE UPDATE ON parking_lot FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_booking_policy_row_version BEFORE UPDATE ON booking_policy FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_parking_floor_row_version BEFORE UPDATE ON parking_floor FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_parking_zone_row_version BEFORE UPDATE ON parking_zone FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_parking_slot_row_version BEFORE UPDATE ON parking_slot FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_slot_reservation_row_version BEFORE UPDATE ON slot_reservation FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_ticket_row_version BEFORE UPDATE ON ticket FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_ticket_renewal_row_version BEFORE UPDATE ON ticket_renewal FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_parking_gate_row_version BEFORE UPDATE ON parking_gate FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_vehicle_entry_exit_log_row_version BEFORE UPDATE ON vehicle_entry_exit_log FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_payment_row_version BEFORE UPDATE ON payment FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();
CREATE TRIGGER trg_news_row_version BEFORE UPDATE ON news FOR EACH ROW EXECUTE FUNCTION set_row_version_and_updated_at();

-- Gắn trigger T2 (block_hard_delete) cho 19 bảng xoá mềm
CREATE TRIGGER trg_account_block_delete BEFORE DELETE ON account FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_position_block_delete BEFORE DELETE ON position FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_employee_block_delete BEFORE DELETE ON employee FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_customer_block_delete BEFORE DELETE ON customer FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_plate_blacklist_block_delete BEFORE DELETE ON plate_blacklist FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_vehicle_type_block_delete BEFORE DELETE ON vehicle_type FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_ticket_type_block_delete BEFORE DELETE ON ticket_type FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_vehicle_block_delete BEFORE DELETE ON vehicle FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_parking_lot_block_delete BEFORE DELETE ON parking_lot FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_booking_policy_block_delete BEFORE DELETE ON booking_policy FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_parking_floor_block_delete BEFORE DELETE ON parking_floor FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_parking_zone_block_delete BEFORE DELETE ON parking_zone FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_parking_slot_block_delete BEFORE DELETE ON parking_slot FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_slot_reservation_block_delete BEFORE DELETE ON slot_reservation FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_ticket_block_delete BEFORE DELETE ON ticket FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_parking_gate_block_delete BEFORE DELETE ON parking_gate FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_payment_block_delete BEFORE DELETE ON payment FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_news_block_delete BEFORE DELETE ON news FOR EACH ROW EXECUTE FUNCTION block_hard_delete();
CREATE TRIGGER trg_notification_block_delete BEFORE DELETE ON notification FOR EACH ROW EXECUTE FUNCTION block_hard_delete();

-- Gắn trigger T3 (append-only) cho activity_log
CREATE TRIGGER trg_activity_log_append_only BEFORE UPDATE OR DELETE ON activity_log FOR EACH ROW EXECUTE FUNCTION block_activity_log_mutation();

-- Gắn trigger T4 (đồng bộ đặt chỗ) cho payment
CREATE TRIGGER trg_payment_sync_reservation AFTER INSERT OR UPDATE OF status ON payment FOR EACH ROW EXECUTE FUNCTION sync_reservation_on_payment();

-- Gắn trigger T5 (đồng bộ ô đỗ) cho vehicle_entry_exit_log
CREATE TRIGGER trg_slot_status_on_traffic AFTER INSERT OR UPDATE ON vehicle_entry_exit_log FOR EACH ROW EXECUTE FUNCTION sync_slot_status_on_traffic();


-- 9. Các view thống kê và báo cáo

-- 9.1. View v_slot_occupancy_by_floor
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
COMMENT ON VIEW v_slot_occupancy_by_floor IS 'Tổng hợp tỷ lệ chiếm dụng ô đỗ theo từng khu vực và tầng bãi xe.';

-- 9.2. View v_revenue_today_by_method
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
COMMENT ON VIEW v_revenue_today_by_method IS 'Doanh thu trong ngày hôm nay phân theo tiền mặt và quét mã VietQR.';

-- 9.3. View v_traffic_by_hour
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
COMMENT ON VIEW v_traffic_by_hour IS 'Mật độ xe ra vào theo từng khung giờ trong ngày giúp nhận biết giờ cao điểm.';

-- 9.4. View v_ai_recognition_stats
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
COMMENT ON VIEW v_ai_recognition_stats IS 'Thống kê hiệu quả nhận diện biển số của mô hình camera AI theo ngày.';

-- 9.5. View v_customer_status_summary
CREATE VIEW v_customer_status_summary AS
SELECT
    COUNT(*)::BIGINT AS total_customers,
    COUNT(*) FILTER (WHERE status = 'ACTIVE')::BIGINT AS active_customers,
    COUNT(*) FILTER (WHERE status = 'SUSPENDED')::BIGINT AS suspended_customers,
    COUNT(*) FILTER (WHERE status = 'BLACKLISTED')::BIGINT AS blacklisted_customers
FROM customer
WHERE deleted_at IS NULL;
COMMENT ON VIEW v_customer_status_summary IS 'Số lượng khách hàng phân theo trạng thái tài khoản và hoạt động gửi xe.';

-- 9.6. View v_revenue_statistics
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
COMMENT ON VIEW v_revenue_statistics IS 'Báo cáo doanh thu bán vé và gia hạn vé theo chu kỳ tháng, quý, năm.';

-- 9.7. View v_vehicle_traffic_daily
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
COMMENT ON VIEW v_vehicle_traffic_daily IS 'Lưu lượng xe vào, xe ra và số xe còn đỗ lại trong bãi theo từng ngày.';

-- 9.8. View v_customer_vehicle_summary
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
COMMENT ON VIEW v_customer_vehicle_summary IS 'Tóm tắt danh sách phương tiện và tình trạng vé của từng khách hàng.';

-- 9.9. View v_booking_overview
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
COMMENT ON VIEW v_booking_overview IS 'Tổng quan các lượt đặt chỗ kèm thông tin khách hàng, xe và giao dịch cọc.';

COMMIT;
