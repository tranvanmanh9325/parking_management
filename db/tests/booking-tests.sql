-- ==============================================================================
-- E2E PURE-SQL VERIFICATION SUITE: ADVANCE SLOT BOOKING MANAGEMENT (R3.2)
-- ==============================================================================
-- Repository : parking_management
-- Module     : Advance Slot Booking Management (Milestone M4)
-- Execution  : psql -v ON_ERROR_STOP=1 -f db/tests/booking-tests.sql
-- Invariant  : Entire suite executes inside a single BEGIN ... ROLLBACK transaction.
--              Guarantees ZERO residual data and zero side effects on the database.
-- ==============================================================================

\set ON_ERROR_STOP on
\set VERBOSITY verbose

BEGIN;

-- -----------------------------------------------------------------------------
-- 0. TEST HARNESS SETUP (TEMPORARY TABLES & HELPERS)
-- -----------------------------------------------------------------------------
CREATE TEMP TABLE IF NOT EXISTS test_results (
    group_id INT PRIMARY KEY,
    group_title TEXT NOT NULL,
    test_status TEXT NOT NULL,
    detail TEXT,
    executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE PROCEDURE pg_temp.record_test_result(
    p_group_id INT,
    p_title TEXT,
    p_passed BOOLEAN,
    p_detail TEXT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO test_results (group_id, group_title, test_status, detail)
    VALUES (p_group_id, p_title, CASE WHEN p_passed THEN 'PASSED' ELSE 'FAILED' END, p_detail);

    IF p_passed THEN
        RAISE NOTICE '>>> [PASS] Group %: %', to_char(p_group_id, 'FM00'), p_title;
    ELSE
        RAISE EXCEPTION '>>> [FAIL] Group %: % - Details: %', to_char(p_group_id, 'FM00'), p_title, p_detail;
    END IF;
END;
$$;

-- Adapter helper for fn_create_booking to gracefully handle signature variations
CREATE OR REPLACE FUNCTION pg_temp.call_create_booking(
    p_customer_id BIGINT,
    p_vehicle_id BIGINT,
    p_slot_id BIGINT,
    p_from TIMESTAMPTZ,
    p_until TIMESTAMPTZ,
    p_channel VARCHAR DEFAULT 'CUSTOMER_PORTAL',
    p_name VARCHAR DEFAULT NULL,
    p_phone VARCHAR DEFAULT NULL,
    p_notes TEXT DEFAULT NULL
)
RETURNS TABLE (
    booking_id BIGINT,
    booking_code VARCHAR,
    payment_id BIGINT,
    deposit_amount NUMERIC,
    hold_expires_at TIMESTAMPTZ,
    status VARCHAR
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_lot_id BIGINT;
    v_res_id BIGINT;
BEGIN
    SELECT pf.lot_id INTO v_lot_id
    FROM parking_slot ps
    JOIN parking_zone pz ON pz.id = ps.zone_id
    JOIN parking_floor pf ON pf.id = pz.floor_id
    WHERE ps.id = p_slot_id;

    -- Directly invoke fn_create_booking(lot_id, cust_id, veh_id, slot_id, from, until, channel, name, phone, notes, created_by)
    v_res_id := fn_create_booking(
        v_lot_id,
        p_customer_id,
        p_vehicle_id,
        p_slot_id,
        p_from,
        p_until,
        COALESCE(p_channel, 'CUSTOMER_PORTAL'),
        p_name,
        p_phone,
        p_notes,
        NULL
    );

    RETURN QUERY
    SELECT
        r.id,
        r.code,
        p.id,
        r.deposit_amount,
        r.hold_expires_at,
        r.status
    FROM slot_reservation r
    LEFT JOIN payment p ON p.reservation_id = r.id AND p.deleted_at IS NULL
    WHERE r.id = v_res_id;
END;
$$;

-- Adapter helper for fn_cancel_booking
CREATE OR REPLACE FUNCTION pg_temp.call_cancel_booking(
    p_booking_id BIGINT,
    p_cancelled_by BIGINT,
    p_reason TEXT DEFAULT NULL
)
RETURNS TABLE (
    booking_id BIGINT,
    old_status VARCHAR,
    new_status VARCHAR,
    refund_issued BOOLEAN,
    deposit_refunded NUMERIC
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_json JSONB;
BEGIN
    v_json := fn_cancel_booking(p_booking_id, p_cancelled_by, p_reason);

    booking_id := (v_json->>'reservation_id')::BIGINT;
    old_status := 'CONFIRMED';
    new_status := v_json->>'status';
    refund_issued := (v_json->>'refund_eligible')::BOOLEAN;
    deposit_refunded := (v_json->>'refund_amount')::NUMERIC;
    RETURN NEXT;
END;
$$;

-- Adapter helper for fn_expire_stale_bookings
CREATE OR REPLACE FUNCTION pg_temp.call_expire_stale_bookings()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INT;
    v_json JSONB;
BEGIN
    BEGIN
        SELECT fn_expire_stale_bookings() INTO v_count;
        RETURN v_count;
    EXCEPTION WHEN datatype_mismatch THEN
        EXECUTE 'SELECT fn_expire_stale_bookings()' INTO v_json;
        RETURN COALESCE((v_json->>'expired_count')::INT, 0) + COALESCE((v_json->>'noshow_count')::INT, 0);
    END;
END;
$$;

DO $$
BEGIN
    RAISE NOTICE '==============================================================================';
    RAISE NOTICE 'STARTING 15 TEST GROUPS VERIFICATION (M4 ADVANCE SLOT BOOKING)';
    RAISE NOTICE '==============================================================================';
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 01: Booking created successfully (Happy Path)
-- Expected: Reservation created in PENDING_PAYMENT, hold_expires_at set,
--           matching UNPAID deposit payment created.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot_id BIGINT;
    v_from TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '1 day';
    v_until TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '1 day 2 hours';
    v_bk RECORD;
    v_rsv_status VARCHAR;
    v_pay_status VARCHAR;
    v_pay_amount NUMERIC;
BEGIN
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;
    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.customer_id = v_cust_id AND v.deleted_at IS NULL LIMIT 1;
    
    -- Pick an available slot matching vehicle type
    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    SELECT * INTO v_bk FROM pg_temp.call_create_booking(
        v_cust_id, v_veh_id, v_slot_id, v_from, v_until, 'CUSTOMER_PORTAL', NULL, NULL, 'Test Group 01 Happy Path'
    );

    IF v_bk.booking_id IS NULL THEN
        CALL pg_temp.record_test_result(1, 'booking created successfully', FALSE, 'fn_create_booking returned NULL booking_id');
        RETURN;
    END IF;

    SELECT status INTO v_rsv_status FROM slot_reservation WHERE id = v_bk.booking_id;
    IF v_rsv_status <> 'PENDING_PAYMENT' THEN
        CALL pg_temp.record_test_result(1, 'booking created successfully', FALSE, 'Expected PENDING_PAYMENT but found: ' || COALESCE(v_rsv_status, 'NULL'));
        RETURN;
    END IF;

    SELECT status, amount INTO v_pay_status, v_pay_amount FROM payment WHERE reservation_id = v_bk.booking_id;
    IF v_pay_status <> 'UNPAID' THEN
        CALL pg_temp.record_test_result(1, 'booking created successfully', FALSE, 'Expected UNPAID deposit payment but found: ' || COALESCE(v_pay_status, 'NULL'));
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(1, 'booking created successfully', TRUE, 'Booking ID: ' || v_bk.booking_id || ', Payment ID: ' || v_bk.payment_id);
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 02: Overlapping booking on the same slot blocked (GiST slot exclusion)
-- Expected: Attempting to book the same slot with overlapping time raises PROP-* error
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust1_id BIGINT;
    v_veh1_id BIGINT;
    v_cust2_id BIGINT;
    v_veh2_id BIGINT;
    v_slot_id BIGINT;
    v_from TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '2 days';
    v_until TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '2 days 4 hours';
    v_bk1 RECORD;
    v_bk2 RECORD;
    v_caught BOOLEAN := FALSE;
    v_err_msg TEXT;
BEGIN
    SELECT c.id INTO v_cust1_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' ORDER BY c.id LIMIT 1;
    SELECT v.id INTO v_veh1_id FROM vehicle v WHERE v.customer_id = v_cust1_id AND v.deleted_at IS NULL LIMIT 1;

    SELECT c.id INTO v_cust2_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' AND c.id <> v_cust1_id ORDER BY c.id LIMIT 1;
    SELECT v.id INTO v_veh2_id FROM vehicle v WHERE v.customer_id = v_cust2_id AND v.deleted_at IS NULL LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh1_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    -- Create initial booking
    SELECT * INTO v_bk1 FROM pg_temp.call_create_booking(
        v_cust1_id, v_veh1_id, v_slot_id, v_from, v_until, 'CUSTOMER_PORTAL'
    );

    -- Attempt overlapping booking on same slot (shift 1 hour into existing window)
    BEGIN
        SELECT * INTO v_bk2 FROM pg_temp.call_create_booking(
            v_cust2_id, v_veh2_id, v_slot_id, v_from + INTERVAL '1 hour', v_until + INTERVAL '1 hour', 'CUSTOMER_PORTAL'
        );
    EXCEPTION WHEN OTHERS THEN
        v_caught := TRUE;
        v_err_msg := SQLERRM;
    END;

    IF NOT v_caught THEN
        CALL pg_temp.record_test_result(2, 'overlapping booking on the same slot blocked (GiST slot exclusion)', FALSE, 'Overlapping booking was allowed without exception!');
    ELSE
        CALL pg_temp.record_test_result(2, 'overlapping booking on the same slot blocked (GiST slot exclusion)', TRUE, 'Correctly rejected with: ' || v_err_msg);
    END IF;
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 03: Same vehicle booking two overlapping slots blocked (GiST vehicle exclusion)
-- Expected: Same vehicle booking two different slots in overlapping time raises PROP-* error
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot1_id BIGINT;
    v_slot2_id BIGINT;
    v_from TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '3 days';
    v_until TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '3 days 3 hours';
    v_bk1 RECORD;
    v_bk2 RECORD;
    v_caught BOOLEAN := FALSE;
    v_err_msg TEXT;
BEGIN
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;
    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.customer_id = v_cust_id AND v.deleted_at IS NULL LIMIT 1;

    -- Pick two distinct available slots compatible with vehicle
    SELECT ps.id INTO v_slot1_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    ORDER BY ps.id ASC LIMIT 1;

    SELECT ps.id INTO v_slot2_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL AND ps.id <> v_slot1_id
    ORDER BY ps.id ASC LIMIT 1;

    -- First booking on slot1
    SELECT * INTO v_bk1 FROM pg_temp.call_create_booking(
        v_cust_id, v_veh_id, v_slot1_id, v_from, v_until, 'CUSTOMER_PORTAL'
    );

    -- Attempt second booking for SAME vehicle on slot2 during overlapping window
    BEGIN
        SELECT * INTO v_bk2 FROM pg_temp.call_create_booking(
            v_cust_id, v_veh_id, v_slot2_id, v_from + INTERVAL '30 minutes', v_until + INTERVAL '30 minutes', 'CUSTOMER_PORTAL'
        );
    EXCEPTION WHEN OTHERS THEN
        v_caught := TRUE;
        v_err_msg := SQLERRM;
    END;

    IF NOT v_caught THEN
        CALL pg_temp.record_test_result(3, 'same vehicle booking two overlapping slots blocked (GiST vehicle exclusion)', FALSE, 'Same vehicle booked 2 overlapping slots without rejection!');
    ELSE
        CALL pg_temp.record_test_result(3, 'same vehicle booking two overlapping slots blocked (GiST vehicle exclusion)', TRUE, 'Correctly rejected with: ' || v_err_msg);
    END IF;
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 04: Another vehicle entering a booked slot blocked
-- Expected: fn_guard_slot_reservation_on_entry prevents a different vehicle from
--           checking in to an active reserved slot during the booking window.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_owner_id BIGINT;
    v_veh_owner_id BIGINT;
    v_plate_owner VARCHAR;
    v_veh_other_id BIGINT;
    v_plate_other VARCHAR;
    v_slot_id BIGINT;
    v_gate_id BIGINT;
    v_rsv_id BIGINT;
    v_caught BOOLEAN := FALSE;
    v_err_msg TEXT;
BEGIN
    SELECT c.id INTO v_cust_owner_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' ORDER BY c.id ASC LIMIT 1;
    SELECT v.id, v.license_plate INTO v_veh_owner_id, v_plate_owner FROM vehicle v WHERE v.customer_id = v_cust_owner_id AND v.deleted_at IS NULL LIMIT 1;

    SELECT v.id, v.license_plate INTO v_veh_other_id, v_plate_other
    FROM vehicle v
    WHERE v.deleted_at IS NULL AND v.id <> v_veh_owner_id
      AND NOT EXISTS (SELECT 1 FROM vehicle_entry_exit_log l WHERE l.vehicle_id = v.id AND l.exit_time IS NULL)
    LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_owner_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    SELECT g.id INTO v_gate_id FROM parking_gate g WHERE g.direction = 'IN' AND g.deleted_at IS NULL LIMIT 1;

    -- Create reservation covering present time
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until, status, booking_channel
    ) VALUES (
        'RSV-TEST-GRP04-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_owner_id, v_veh_owner_id,
        CURRENT_TIMESTAMP - INTERVAL '10 minutes',
        CURRENT_TIMESTAMP + INTERVAL '1 hour',
        'CONFIRMED',
        'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_id;

    -- Other vehicle attempts barrier check-in into v_slot_id
    BEGIN
        INSERT INTO vehicle_entry_exit_log (
            session_code, entry_gate_id, slot_id, vehicle_id, license_plate, entry_time
        ) VALUES (
            'SES-TEST-GRP04-' || substr(md5(random()::text), 1, 8),
            v_gate_id, v_slot_id, v_veh_other_id, v_plate_other, CURRENT_TIMESTAMP
        );
    EXCEPTION WHEN OTHERS THEN
        v_caught := TRUE;
        v_err_msg := SQLERRM;
    END;

    IF NOT v_caught THEN
        CALL pg_temp.record_test_result(4, 'another vehicle entering a booked slot blocked', FALSE, 'Other vehicle entered booked slot without being blocked!');
    ELSE
        CALL pg_temp.record_test_result(4, 'another vehicle entering a booked slot blocked', TRUE, 'Correctly blocked unauthorized entry: ' || v_err_msg);
    END IF;
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 05: Booking owner entering on time -> reservation CHECKED_IN and reservation_id linked
-- Expected: Matching vehicle entering within [from - early, from + grace] links
--           reservation_id in session log and sets reservation status to CHECKED_IN.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_plate VARCHAR;
    v_slot_id BIGINT;
    v_gate_id BIGINT;
    v_rsv_id BIGINT;
    v_session_id BIGINT;
    v_linked_rsv_id BIGINT;
    v_rsv_status VARCHAR;
    v_checked_in_at TIMESTAMPTZ;
BEGIN
    SELECT v.id, v.customer_id, v.license_plate INTO v_veh_id, v_cust_id, v_plate
    FROM vehicle v
    JOIN customer c ON c.id = v.customer_id
    WHERE v.deleted_at IS NULL AND c.deleted_at IS NULL AND c.status = 'ACTIVE'
      AND NOT EXISTS (SELECT 1 FROM vehicle_entry_exit_log l WHERE l.vehicle_id = v.id AND l.exit_time IS NULL)
    LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    SELECT g.id INTO v_gate_id FROM parking_gate g WHERE g.direction = 'IN' AND g.deleted_at IS NULL LIMIT 1;

    -- Create reservation confirmed for now
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until, status, booking_channel
    ) VALUES (
        'RSV-TEST-GRP05-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP - INTERVAL '5 minutes',
        CURRENT_TIMESTAMP + INTERVAL '2 hours',
        'CONFIRMED',
        'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_id;

    -- Owner vehicle enters barrier
    INSERT INTO vehicle_entry_exit_log (
        session_code, entry_gate_id, slot_id, vehicle_id, license_plate, entry_time
    ) VALUES (
        'SES-TEST-GRP05-' || substr(md5(random()::text), 1, 8),
        v_gate_id, v_slot_id, v_veh_id, v_plate, CURRENT_TIMESTAMP
    ) RETURNING id, reservation_id INTO v_session_id, v_linked_rsv_id;

    SELECT status, checked_in_at INTO v_rsv_status, v_checked_in_at
    FROM slot_reservation WHERE id = v_rsv_id;

    IF v_linked_rsv_id IS DISTINCT FROM v_rsv_id THEN
        CALL pg_temp.record_test_result(5, 'booking owner entering on time -> reservation CHECKED_IN and reservation_id linked', FALSE, 'Session reservation_id was not automatically linked! Expected ' || v_rsv_id || ' but got ' || COALESCE(v_linked_rsv_id::text, 'NULL'));
        RETURN;
    END IF;

    IF v_rsv_status <> 'CHECKED_IN' OR v_checked_in_at IS NULL THEN
        CALL pg_temp.record_test_result(5, 'booking owner entering on time -> reservation CHECKED_IN and reservation_id linked', FALSE, 'Reservation status is not CHECKED_IN (status: ' || COALESCE(v_rsv_status, 'NULL') || ', checked_in_at: ' || COALESCE(v_checked_in_at::text, 'NULL') || ')');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(5, 'booking owner entering on time -> reservation CHECKED_IN and reservation_id linked', TRUE, 'Session ' || v_session_id || ' linked to Reservation ' || v_rsv_id || ' with status CHECKED_IN');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 06: Exit -> COMPLETED
-- Expected: Closing the session (exit_time IS NOT NULL) auto-transitions linked
--           reservation to COMPLETED, sets completed_at, and frees the slot.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_plate VARCHAR;
    v_slot_id BIGINT;
    v_gate_in_id BIGINT;
    v_gate_out_id BIGINT;
    v_rsv_id BIGINT;
    v_session_id BIGINT;
    v_rsv_status VARCHAR;
    v_completed_at TIMESTAMPTZ;
    v_slot_status VARCHAR;
BEGIN
    SELECT v.id, v.customer_id, v.license_plate INTO v_veh_id, v_cust_id, v_plate
    FROM vehicle v
    JOIN customer c ON c.id = v.customer_id
    WHERE v.deleted_at IS NULL AND c.deleted_at IS NULL AND c.status = 'ACTIVE'
      AND NOT EXISTS (SELECT 1 FROM vehicle_entry_exit_log l WHERE l.vehicle_id = v.id AND l.exit_time IS NULL)
    LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    SELECT g.id INTO v_gate_in_id FROM parking_gate g WHERE g.direction = 'IN' AND g.deleted_at IS NULL LIMIT 1;
    SELECT g.id INTO v_gate_out_id FROM parking_gate g WHERE g.direction = 'OUT' AND g.deleted_at IS NULL LIMIT 1;

    -- Create checked-in reservation
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until, status, checked_in_at, booking_channel
    ) VALUES (
        'RSV-TEST-GRP06-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP - INTERVAL '1 hour',
        CURRENT_TIMESTAMP + INTERVAL '1 hour',
        'CHECKED_IN',
        CURRENT_TIMESTAMP - INTERVAL '50 minutes',
        'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_id;

    -- Create open session linked to reservation
    INSERT INTO vehicle_entry_exit_log (
        session_code, entry_gate_id, slot_id, vehicle_id, license_plate, entry_time, reservation_id
    ) VALUES (
        'SES-TEST-GRP06-' || substr(md5(random()::text), 1, 8),
        v_gate_in_id, v_slot_id, v_veh_id, v_plate, CURRENT_TIMESTAMP - INTERVAL '50 minutes', v_rsv_id
    ) RETURNING id INTO v_session_id;

    -- Vehicle exits
    UPDATE vehicle_entry_exit_log
    SET exit_time = CURRENT_TIMESTAMP,
        exit_gate_id = v_gate_out_id,
        fee_amount = 0.00
    WHERE id = v_session_id;

    SELECT status, completed_at INTO v_rsv_status, v_completed_at
    FROM slot_reservation WHERE id = v_rsv_id;

    SELECT status INTO v_slot_status FROM parking_slot WHERE id = v_slot_id;

    IF v_rsv_status <> 'COMPLETED' OR v_completed_at IS NULL THEN
        CALL pg_temp.record_test_result(6, 'exit -> COMPLETED', FALSE, 'Reservation did not transition to COMPLETED (status: ' || COALESCE(v_rsv_status, 'NULL') || ')');
        RETURN;
    END IF;

    IF v_slot_status <> 'AVAILABLE' THEN
        CALL pg_temp.record_test_result(6, 'exit -> COMPLETED', FALSE, 'Slot did not recompute to AVAILABLE (status: ' || COALESCE(v_slot_status, 'NULL') || ')');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(6, 'exit -> COMPLETED', TRUE, 'Reservation completed and slot status recomputed to AVAILABLE.');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 07: Deposit PAID -> auto CONFIRMED
-- Expected: Updating deposit payment status to PAID automatically updates
--           the reservation from PENDING_PAYMENT to CONFIRMED.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot_id BIGINT;
    v_rsv_id BIGINT;
    v_pay_id BIGINT;
    v_rsv_status VARCHAR;
BEGIN
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;
    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.customer_id = v_cust_id AND v.deleted_at IS NULL LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until,
        status, deposit_amount, hold_expires_at, booking_channel
    ) VALUES (
        'RSV-TEST-GRP07-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP + INTERVAL '4 days',
        CURRENT_TIMESTAMP + INTERVAL '4 days 2 hours',
        'PENDING_PAYMENT',
        50000.00,
        CURRENT_TIMESTAMP + INTERVAL '15 minutes',
        'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_id;

    INSERT INTO payment (
        code, reservation_id, amount, method, status
    ) VALUES (
        'PAY-TEST-GRP07-' || substr(md5(random()::text), 1, 8),
        v_rsv_id, 50000.00, 'VIETQR', 'UNPAID'
    ) RETURNING id INTO v_pay_id;

    -- Process payment settlement
    UPDATE payment
    SET status = 'PAID',
        paid_at = CURRENT_TIMESTAMP
    WHERE id = v_pay_id;

    SELECT status INTO v_rsv_status FROM slot_reservation WHERE id = v_rsv_id;

    IF v_rsv_status <> 'CONFIRMED' THEN
        CALL pg_temp.record_test_result(7, 'deposit PAID -> auto CONFIRMED', FALSE, 'Reservation did not auto-confirm upon payment settlement (status: ' || COALESCE(v_rsv_status, 'NULL') || ')');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(7, 'deposit PAID -> auto CONFIRMED', TRUE, 'Payment PAID triggered reservation CONFIRMED successfully.');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 08: Past hold -> EXPIRED
-- Expected: fn_expire_stale_bookings transitions PENDING_PAYMENT reservations
--           past hold_expires_at to EXPIRED, and cancels UNPAID payments.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot_id BIGINT;
    v_rsv_id BIGINT;
    v_pay_id BIGINT;
    v_rsv_status VARCHAR;
    v_pay_status VARCHAR;
    v_affected INT;
BEGIN
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;
    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.customer_id = v_cust_id AND v.deleted_at IS NULL LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until,
        status, deposit_amount, hold_expires_at, booking_channel
    ) VALUES (
        'RSV-TEST-GRP08-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP + INTERVAL '4 days 4 hours',
        CURRENT_TIMESTAMP + INTERVAL '4 days 6 hours',
        'PENDING_PAYMENT',
        50000.00,
        CURRENT_TIMESTAMP - INTERVAL '5 minutes', -- Hold timed out!
        'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_id;

    INSERT INTO payment (
        code, reservation_id, amount, method, status
    ) VALUES (
        'PAY-TEST-GRP08-' || substr(md5(random()::text), 1, 8),
        v_rsv_id, 50000.00, 'VIETQR', 'UNPAID'
    ) RETURNING id INTO v_pay_id;

    v_affected := pg_temp.call_expire_stale_bookings();

    SELECT status INTO v_rsv_status FROM slot_reservation WHERE id = v_rsv_id;
    SELECT status INTO v_pay_status FROM payment WHERE id = v_pay_id;

    IF v_rsv_status <> 'EXPIRED' THEN
        CALL pg_temp.record_test_result(8, 'past hold -> EXPIRED', FALSE, 'Reservation did not transition to EXPIRED (status: ' || COALESCE(v_rsv_status, 'NULL') || ')');
        RETURN;
    END IF;

    IF v_pay_status <> 'CANCELLED' THEN
        CALL pg_temp.record_test_result(8, 'past hold -> EXPIRED', FALSE, 'Deposit payment was not cancelled (status: ' || COALESCE(v_pay_status, 'NULL') || ')');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(8, 'past hold -> EXPIRED', TRUE, 'Stale hold expired successfully and deposit payment cancelled.');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 09: Past grace -> NO_SHOW
-- Expected: fn_expire_stale_bookings transitions CONFIRMED reservations past
--           (reserved_from + grace_minutes) without check-in to NO_SHOW.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot_id BIGINT;
    v_rsv_id BIGINT;
    v_pay_id BIGINT;
    v_rsv_status VARCHAR;
    v_no_show_at TIMESTAMPTZ;
    v_pay_status VARCHAR;
    v_affected INT;
BEGIN
    SELECT v.id, v.customer_id INTO v_veh_id, v_cust_id
    FROM vehicle v
    JOIN customer c ON c.id = v.customer_id
    WHERE v.deleted_at IS NULL AND c.deleted_at IS NULL AND c.status = 'ACTIVE'
      AND NOT EXISTS (
          SELECT 1 FROM slot_reservation r
          WHERE r.vehicle_id = v.id AND r.deleted_at IS NULL
            AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN')
            AND tstzrange(r.reserved_from, r.reserved_until, '[)') && tstzrange(CURRENT_TIMESTAMP - INTERVAL '45 minutes', CURRENT_TIMESTAMP + INTERVAL '1 hour', '[)')
      )
    ORDER BY v.id DESC
    LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM slot_reservation r
          WHERE r.slot_id = ps.id AND r.deleted_at IS NULL
            AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN')
            AND tstzrange(r.reserved_from, r.reserved_until, '[)') && tstzrange(CURRENT_TIMESTAMP - INTERVAL '45 minutes', CURRENT_TIMESTAMP + INTERVAL '1 hour', '[)')
      )
    ORDER BY ps.id DESC
    LIMIT 1;

    -- Confirmed reservation whose grace window expired in the past
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until,
        status, deposit_amount, booking_channel
    ) VALUES (
        'RSV-TEST-GRP09-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP - INTERVAL '45 minutes', -- Past grace!
        CURRENT_TIMESTAMP + INTERVAL '1 hour',
        'CONFIRMED',
        50000.00,
        'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_id;

    INSERT INTO payment (
        code, reservation_id, amount, method, status, paid_at
    ) VALUES (
        'PAY-TEST-GRP09-' || substr(md5(random()::text), 1, 8),
        v_rsv_id, 50000.00, 'VIETQR', 'PAID', CURRENT_TIMESTAMP - INTERVAL '1 hour'
    ) RETURNING id INTO v_pay_id;

    v_affected := pg_temp.call_expire_stale_bookings();

    SELECT status, no_show_at INTO v_rsv_status, v_no_show_at FROM slot_reservation WHERE id = v_rsv_id;
    SELECT status INTO v_pay_status FROM payment WHERE id = v_pay_id;

    IF v_rsv_status <> 'NO_SHOW' OR v_no_show_at IS NULL THEN
        CALL pg_temp.record_test_result(9, 'past grace -> NO_SHOW', FALSE, 'Reservation did not transition to NO_SHOW (status: ' || COALESCE(v_rsv_status, 'NULL') || ')');
        RETURN;
    END IF;

    IF v_pay_status <> 'PAID' THEN
        CALL pg_temp.record_test_result(9, 'past grace -> NO_SHOW', FALSE, 'Deposit payment should be retained as PAID for forfeit (status: ' || COALESCE(v_pay_status, 'NULL') || ')');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(9, 'past grace -> NO_SHOW', TRUE, 'Grace expiration marked reservation as NO_SHOW and forfeited deposit.');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 10: Early cancel refunds deposit, late cancel forfeits
-- Expected: fn_cancel_booking refunds (payment -> REFUNDED) if cancelled before
--           cancel_free_before_minutes, and forfeits (payment remains PAID) if late.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot1_id BIGINT;
    v_slot2_id BIGINT;
    v_emp_acc_id BIGINT;
    v_rsv_early_id BIGINT;
    v_pay_early_id BIGINT;
    v_rsv_late_id BIGINT;
    v_pay_late_id BIGINT;
    v_res_early RECORD;
    v_res_late RECORD;
    v_early_pay_status VARCHAR;
    v_late_pay_status VARCHAR;
BEGIN
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;
    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.customer_id = v_cust_id AND v.deleted_at IS NULL LIMIT 1;
    SELECT a.id INTO v_emp_acc_id FROM account a JOIN employee e ON e.account_id = a.id WHERE a.deleted_at IS NULL LIMIT 1;

    SELECT ps.id INTO v_slot1_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    ORDER BY ps.id ASC LIMIT 1;

    SELECT ps.id INTO v_slot2_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL AND ps.id <> v_slot1_id
    ORDER BY ps.id ASC LIMIT 1;

    -- 10a: Early cancel reservation (reserved_from is 5 hours away > 60m threshold)
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until,
        status, deposit_amount, booking_channel
    ) VALUES (
        'RSV-TEST-GRP10A-' || substr(md5(random()::text), 1, 8),
        v_slot1_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP + INTERVAL '5 hours',
        CURRENT_TIMESTAMP + INTERVAL '7 hours',
        'CONFIRMED', 50000.00, 'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_early_id;

    INSERT INTO payment (
        code, reservation_id, amount, method, status, paid_at
    ) VALUES (
        'PAY-TEST-GRP10A-' || substr(md5(random()::text), 1, 8),
        v_rsv_early_id, 50000.00, 'VIETQR', 'PAID', CURRENT_TIMESTAMP
    ) RETURNING id INTO v_pay_early_id;

    SELECT * INTO v_res_early FROM pg_temp.call_cancel_booking(v_rsv_early_id, v_emp_acc_id, 'Customer requested early cancellation');
    SELECT status INTO v_early_pay_status FROM payment WHERE id = v_pay_early_id;

    IF v_early_pay_status <> 'REFUNDED' THEN
        CALL pg_temp.record_test_result(10, 'early cancel refunds deposit, late cancel forfeits', FALSE, 'Early cancel did not refund deposit (status: ' || COALESCE(v_early_pay_status, 'NULL') || ')');
        RETURN;
    END IF;

    -- 10b: Late cancel reservation (reserved_from is 20 minutes away < 60m threshold)
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until,
        status, deposit_amount, booking_channel
    ) VALUES (
        'RSV-TEST-GRP10B-' || substr(md5(random()::text), 1, 8),
        v_slot2_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP + INTERVAL '20 minutes',
        CURRENT_TIMESTAMP + INTERVAL '2 hours 20 minutes',
        'CONFIRMED', 50000.00, 'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_late_id;

    INSERT INTO payment (
        code, reservation_id, amount, method, status, paid_at
    ) VALUES (
        'PAY-TEST-GRP10B-' || substr(md5(random()::text), 1, 8),
        v_rsv_late_id, 50000.00, 'VIETQR', 'PAID', CURRENT_TIMESTAMP
    ) RETURNING id INTO v_pay_late_id;

    SELECT * INTO v_res_late FROM pg_temp.call_cancel_booking(v_rsv_late_id, v_emp_acc_id, 'Customer requested late cancellation');
    SELECT status INTO v_late_pay_status FROM payment WHERE id = v_pay_late_id;

    IF v_late_pay_status <> 'PAID' THEN
        CALL pg_temp.record_test_result(10, 'early cancel refunds deposit, late cancel forfeits', FALSE, 'Late cancel should forfeit deposit as PAID (status: ' || COALESCE(v_late_pay_status, 'NULL') || ')');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(10, 'early cancel refunds deposit, late cancel forfeits', TRUE, 'Early cancel correctly refunded; late cancel correctly forfeited deposit.');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 11: Invalid status transitions blocked
-- Expected: Trigger blocks leaving terminal states (COMPLETED, CANCELLED,
--           EXPIRED, NO_SHOW) and illegal state matrix jumps.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot_id BIGINT;
    v_rsv_completed_id BIGINT;
    v_rsv_pending_id BIGINT;
    v_caught1 BOOLEAN := FALSE;
    v_caught2 BOOLEAN := FALSE;
BEGIN
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;
    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.customer_id = v_cust_id AND v.deleted_at IS NULL LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    -- Create completed reservation
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until, status, completed_at, booking_channel
    ) VALUES (
        'RSV-TEST-GRP11A-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP - INTERVAL '5 hours',
        CURRENT_TIMESTAMP - INTERVAL '3 hours',
        'COMPLETED', CURRENT_TIMESTAMP - INTERVAL '3 hours', 'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_completed_id;

    -- Attempt 1: Revive COMPLETED -> CONFIRMED (must be blocked)
    BEGIN
        UPDATE slot_reservation SET status = 'CONFIRMED' WHERE id = v_rsv_completed_id;
    EXCEPTION WHEN OTHERS THEN
        v_caught1 := TRUE;
    END;

    -- Create pending reservation
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until, status, hold_expires_at, booking_channel
    ) VALUES (
        'RSV-TEST-GRP11B-' || substr(md5(random()::text), 1, 8),
        v_slot_id, v_cust_id, v_veh_id,
        CURRENT_TIMESTAMP + INTERVAL '5 days',
        CURRENT_TIMESTAMP + INTERVAL '5 days 2 hours',
        'PENDING_PAYMENT',
        CURRENT_TIMESTAMP + INTERVAL '15 minutes',
        'CUSTOMER_PORTAL'
    ) RETURNING id INTO v_rsv_pending_id;

    -- Attempt 2: Illegal leap PENDING_PAYMENT -> COMPLETED (must be blocked)
    BEGIN
        UPDATE slot_reservation SET status = 'COMPLETED' WHERE id = v_rsv_pending_id;
    EXCEPTION WHEN OTHERS THEN
        v_caught2 := TRUE;
    END;

    IF NOT v_caught1 OR NOT v_caught2 THEN
        CALL pg_temp.record_test_result(11, 'invalid status transitions blocked', FALSE, 'Invalid transition was allowed without rejection! (v_caught1=' || v_caught1 || ', v_caught2=' || v_caught2 || ')');
    ELSE
        CALL pg_temp.record_test_result(11, 'invalid status transitions blocked', TRUE, 'Illegal transitions and terminal mutations strictly blocked.');
    END IF;
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 12: BLACKLISTED customer blocked
-- Expected: Attempting to create booking for BLACKLISTED/SUSPENDED customer raises PROP-*
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_slot_id BIGINT;
    v_bk RECORD;
    v_caught BOOLEAN := FALSE;
    v_err_msg TEXT;
BEGIN
    -- Temporarily set a test customer to BLACKLISTED
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' ORDER BY c.id DESC LIMIT 1;
    UPDATE customer SET status = 'BLACKLISTED', status_reason = 'Test violation reason' WHERE id = v_cust_id;

    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.customer_id = v_cust_id AND v.deleted_at IS NULL LIMIT 1;

    SELECT ps.id INTO v_slot_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id
    JOIN vehicle v ON v.id = v_veh_id AND v.vehicle_type_id = savt.vehicle_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    LIMIT 1;

    BEGIN
        SELECT * INTO v_bk FROM pg_temp.call_create_booking(
            v_cust_id, v_veh_id, v_slot_id,
            CURRENT_TIMESTAMP + INTERVAL '5 days 4 hours',
            CURRENT_TIMESTAMP + INTERVAL '5 days 6 hours',
            'CUSTOMER_PORTAL'
        );
    EXCEPTION WHEN OTHERS THEN
        v_caught := TRUE;
        v_err_msg := SQLERRM;
    END;

    IF NOT v_caught THEN
        CALL pg_temp.record_test_result(12, 'BLACKLISTED customer blocked', FALSE, 'Blacklisted customer was permitted to book a slot!');
    ELSE
        CALL pg_temp.record_test_result(12, 'BLACKLISTED customer blocked', TRUE, 'Correctly blocked blacklisted customer: ' || v_err_msg);
    END IF;
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 13: MAINTENANCE slot / wrong vehicle type blocked
-- Expected: Booking on a MAINTENANCE slot or with mismatched vehicle type is blocked.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_cust_id BIGINT;
    v_veh_car_id BIGINT;
    v_veh_ev_id BIGINT;
    v_slot_maint_id BIGINT;
    v_slot_ev_only_id BIGINT;
    v_caught_maint BOOLEAN := FALSE;
    v_caught_type BOOLEAN := FALSE;
    v_bk RECORD;
BEGIN
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;

    -- Pick a CAR vehicle and EV vehicle
    SELECT v.id INTO v_veh_car_id FROM vehicle v JOIN vehicle_type vt ON vt.id = v.vehicle_type_id WHERE vt.code = 'CAR' AND v.deleted_at IS NULL LIMIT 1;
    SELECT v.id INTO v_veh_ev_id FROM vehicle v JOIN vehicle_type vt ON vt.id = v.vehicle_type_id WHERE vt.code = 'EV' AND v.deleted_at IS NULL LIMIT 1;

    -- Setup maintenance slot
    SELECT ps.id INTO v_slot_maint_id
    FROM parking_slot ps
    WHERE ps.deleted_at IS NULL AND ps.status = 'AVAILABLE'
      AND NOT EXISTS (SELECT 1 FROM vehicle_entry_exit_log l WHERE l.slot_id = ps.id AND l.exit_time IS NULL)
      AND NOT EXISTS (SELECT 1 FROM slot_reservation r WHERE r.slot_id = ps.id AND r.deleted_at IS NULL AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN'))
    ORDER BY ps.id ASC LIMIT 1;
    UPDATE parking_slot SET status = 'MAINTENANCE' WHERE id = v_slot_maint_id;

    -- Setup an EV-only slot
    SELECT ps.id INTO v_slot_ev_only_id
    FROM parking_slot ps
    WHERE ps.deleted_at IS NULL AND ps.status = 'AVAILABLE' AND ps.id <> v_slot_maint_id
      AND NOT EXISTS (SELECT 1 FROM vehicle_entry_exit_log l WHERE l.slot_id = ps.id AND l.exit_time IS NULL)
      AND NOT EXISTS (SELECT 1 FROM slot_reservation r WHERE r.slot_id = ps.id AND r.deleted_at IS NULL AND r.status IN ('PENDING_PAYMENT', 'CONFIRMED', 'CHECKED_IN'))
    ORDER BY ps.id DESC LIMIT 1;
    DELETE FROM slot_allowed_vehicle_type WHERE slot_id = v_slot_ev_only_id;
    INSERT INTO slot_allowed_vehicle_type (slot_id, vehicle_type_id)
    SELECT v_slot_ev_only_id, vt.id FROM vehicle_type vt WHERE vt.code = 'EV';

    -- 13a: Attempt booking on MAINTENANCE slot
    BEGIN
        SELECT * INTO v_bk FROM pg_temp.call_create_booking(
            v_cust_id, v_veh_ev_id, v_slot_maint_id,
            CURRENT_TIMESTAMP + INTERVAL '6 days',
            CURRENT_TIMESTAMP + INTERVAL '6 days 2 hours'
        );
    EXCEPTION WHEN OTHERS THEN
        v_caught_maint := TRUE;
    END;

    -- 13b: Attempt booking CAR on EV-only slot
    BEGIN
        SELECT * INTO v_bk FROM pg_temp.call_create_booking(
            v_cust_id, v_veh_car_id, v_slot_ev_only_id,
            CURRENT_TIMESTAMP + INTERVAL '6 days',
            CURRENT_TIMESTAMP + INTERVAL '6 days 2 hours'
        );
    EXCEPTION WHEN OTHERS THEN
        v_caught_type := TRUE;
    END;

    IF NOT v_caught_maint THEN
        CALL pg_temp.record_test_result(13, 'MAINTENANCE slot / wrong vehicle type blocked', FALSE, 'Booking on MAINTENANCE slot was allowed!');
        RETURN;
    END IF;

    IF NOT v_caught_type THEN
        CALL pg_temp.record_test_result(13, 'MAINTENANCE slot / wrong vehicle type blocked', FALSE, 'Vehicle type mismatch was allowed without rejection!');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(13, 'MAINTENANCE slot / wrong vehicle type blocked', TRUE, 'Both MAINTENANCE slot and vehicle type mismatch properly rejected.');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 14: fn_find_available_slots returns correct rows
-- Expected: fn_find_available_slots returns compatible available slots,
--           excluding maintenance slots and overlapping bookings.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_lot_id BIGINT;
    v_car_type_id BIGINT;
    v_slot_avail_id BIGINT;
    v_slot_busy_id BIGINT;
    v_cust_id BIGINT;
    v_veh_id BIGINT;
    v_from TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '6 days';
    v_until TIMESTAMPTZ := CURRENT_TIMESTAMP + INTERVAL '6 days 3 hours';
    v_avail_count INT;
    v_busy_found BOOLEAN;
    v_avail_found BOOLEAN;
BEGIN
    SELECT id INTO v_car_type_id FROM vehicle_type WHERE code = 'CAR';
    SELECT c.id INTO v_cust_id FROM customer c WHERE c.deleted_at IS NULL AND c.status = 'ACTIVE' LIMIT 1;
    SELECT v.id INTO v_veh_id FROM vehicle v WHERE v.vehicle_type_id = v_car_type_id AND v.deleted_at IS NULL LIMIT 1;

    -- Pick two available slots for CAR
    SELECT ps.id INTO v_slot_avail_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id AND savt.vehicle_type_id = v_car_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL
    ORDER BY ps.id ASC LIMIT 1;

    SELECT ps.id INTO v_slot_busy_id
    FROM parking_slot ps
    JOIN slot_allowed_vehicle_type savt ON savt.slot_id = ps.id AND savt.vehicle_type_id = v_car_type_id
    WHERE ps.status = 'AVAILABLE' AND ps.deleted_at IS NULL AND ps.id <> v_slot_avail_id
    ORDER BY ps.id ASC LIMIT 1;

    SELECT pf.lot_id INTO v_lot_id
    FROM parking_slot ps
    JOIN parking_zone pz ON pz.id = ps.zone_id
    JOIN parking_floor pf ON pf.id = pz.floor_id
    WHERE ps.id = v_slot_avail_id;

    -- Make slot_busy occupied by booking
    INSERT INTO slot_reservation (
        code, slot_id, customer_id, vehicle_id, reserved_from, reserved_until, status, booking_channel
    ) VALUES (
        'RSV-TEST-GRP14-' || substr(md5(random()::text), 1, 8),
        v_slot_busy_id, v_cust_id, v_veh_id,
        v_from, v_until, 'CONFIRMED', 'CUSTOMER_PORTAL'
    );

    -- Query available slots
    SELECT EXISTS (
        SELECT 1 FROM fn_find_available_slots(v_lot_id, v_car_type_id, v_from, v_until) WHERE slot_id = v_slot_busy_id
    ) INTO v_busy_found;

    SELECT EXISTS (
        SELECT 1 FROM fn_find_available_slots(v_lot_id, v_car_type_id, v_from, v_until) WHERE slot_id = v_slot_avail_id
    ) INTO v_avail_found;

    IF v_busy_found THEN
        CALL pg_temp.record_test_result(14, 'fn_find_available_slots returns correct rows', FALSE, 'Booked slot appeared in available slots query!');
        RETURN;
    END IF;

    IF NOT v_avail_found THEN
        CALL pg_temp.record_test_result(14, 'fn_find_available_slots returns correct rows', FALSE, 'Free slot did not appear in available slots query!');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(14, 'fn_find_available_slots returns correct rows', TRUE, 'fn_find_available_slots filtered busy slots and returned free slots accurately.');
END;
$$;


-- -----------------------------------------------------------------------------
-- TEST GROUP 15: Running fn_expire_stale_bookings a second time changes nothing (returns 0)
-- Expected: Second consecutive run is 100% idempotent and returns 0.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_first_run INT;
    v_second_run INT;
BEGIN
    -- Run once to clean any pending items
    v_first_run := pg_temp.call_expire_stale_bookings();

    -- Second run immediately after
    v_second_run := pg_temp.call_expire_stale_bookings();

    IF v_second_run <> 0 THEN
        CALL pg_temp.record_test_result(15, 'running fn_expire_stale_bookings a second time changes nothing (returns 0)', FALSE, 'Second execution modified ' || v_second_run || ' rows (expected 0)');
        RETURN;
    END IF;

    CALL pg_temp.record_test_result(15, 'running fn_expire_stale_bookings a second time changes nothing (returns 0)', TRUE, 'Second execution returned 0 (Idempotency confirmed).');
END;
$$;


-- -----------------------------------------------------------------------------
-- FINAL SUITE SUMMARY & ASSERTION
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_failed_count INT;
    v_passed_count INT;
BEGIN
    SELECT count(*) INTO v_passed_count FROM test_results WHERE test_status = 'PASSED';
    SELECT count(*) INTO v_failed_count FROM test_results WHERE test_status = 'FAILED';

    RAISE NOTICE '==============================================================================';
    RAISE NOTICE 'TEST SUITE SUMMARY: % / 15 PASSED, % FAILED', v_passed_count, v_failed_count;
    RAISE NOTICE '==============================================================================';

    IF v_failed_count > 0 OR v_passed_count < 15 THEN
        RAISE EXCEPTION 'TEST SUITE INCOMPLETE OR HAS FAILURES: Passed %, Failed %', v_passed_count, v_failed_count;
    END IF;
END;
$$;

SELECT
    group_id,
    group_title,
    test_status,
    detail
FROM test_results
ORDER BY group_id;

-- Ensure ZERO residual changes on the database
ROLLBACK;
