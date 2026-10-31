package metrics

// State label values of the enum-style families (functions: no mutable package state).
func healthStates() []string { return []string{"ok", "warning", "critical", "unknown"} }

// serverHealthStates are the oob_server_health states: the sensor verdict plus "off"
// for a host that is powered off (audit R2-01).
func serverHealthStates() []string { return []string{"ok", "warning", "critical", "off", "unknown"} }

func powerStates() []string { return []string{"on", "off", "powering_on", "powering_off", "unknown"} }

// allSpecs lists every family, in output order. It returns a fresh slice each call
// (no package-level mutable state, CLAUDE.md rule 4).
func allSpecs() []spec {
	return append(append(append(appSpecs(), historySpecs()...), serverSpecs()...), sensorSpecs()...)
}

func appSpecs() []spec {
	return []spec{
		{"oob_build_info", "Build information; the value is always 1.", Gauge},
		{"oob_process_start_time_seconds", "Start time of the process, Unix seconds.", Gauge},
		{"oob_process_goroutines", "Goroutines that currently exist.", Gauge},
		{"oob_process_heap_alloc_bytes", "Bytes of allocated heap objects.", Gauge},
		{"oob_process_memory_sys_bytes", "Bytes of memory obtained from the OS by the Go runtime.", Gauge},
		{"oob_process_gc_cycles_total", "Completed garbage collection cycles.", Counter},
		{"oob_audit_chain_ok", "1 when the audit hash chain verified at startup, 0 when it is broken.", Gauge},
		{"oob_audit_shipper_enabled", "1 when GELF audit shipping is configured, 0 when it is off.", Gauge},
		{"oob_audit_shipper_connected", "1 when the GELF audit shipper is connected.", Gauge},
		{"oob_audit_shipper_queued", "Audit records waiting to be shipped.", Gauge},
		{"oob_audit_shipper_dropped_total", "Audit records the shipper dropped (the database copy is kept).", Counter},
		{"oob_audit_shipper_tls", "1 when the GELF audit shipper uses TLS with a pinned certificate.", Gauge},
		{"oob_audit_shipper_pin_mismatch", "1 while shipping is paused because the GELF server's certificate does not match the pin.", Gauge},
		{"oob_audit_shipper_reconnects_total", "Times the GELF shipper connected again after its first connection.", Counter},
		{"oob_audit_shipper_last_success_timestamp_seconds", "When the GELF shipper last wrote an audit record, Unix seconds (0: never).", Gauge},
		{"oob_login_failures_total", "Failed sign-in attempts since start, by stage (password, totp).", Counter},
		{"oob_console_sessions_active", "Console sessions open now, by type (vnc, serial).", Gauge},
		{"oob_notify_target_failing", "1 when a notification target keeps failing.", Gauge},
		{"oob_notify_target_consecutive_failures", "Messages to a target that failed after every retry, in a row.", Gauge},
		{"oob_notify_sent_total", "Notifications delivered to a target since start.", Counter},
		{"oob_notify_dropped_total", "Notifications dropped for a target (queue full or rate limited) since start.", Counter},
		{"oob_servers", "Servers in the effective registry.", Gauge},
		{"oob_firmware_catalog_published_timestamp_seconds", "When the vendor firmware catalog in use was published, " +
			"Unix seconds (0: none imported, or no date).", Gauge},
		{"oob_firmware_catalog_last_check_timestamp_seconds", "When the firmware update check last ran, Unix seconds, " +
			"labelled with its result (imported, held, not_modified, download, size, signature, untrusted_key, parse, disabled).", Gauge},
		{"oob_firmware_catalog_check_failures_total", "Failed firmware update checks since start, by class (download, " +
			"size, signature, untrusted_key, parse).", Counter},
	}
}

func serverSpecs() []spec {
	return []spec{
		{"oob_server_info", "Server identity; the value is always 1.", Gauge},
		{"oob_server_up", "1 when the last BMC poll succeeded.", Gauge},
		{"oob_server_stale", "1 when the cached data is older than the stale threshold (or there is none).", Gauge},
		{"oob_server_paused", "1 when polling is paused because the BMC certificate does not match its pin.", Gauge},
		{"oob_server_consecutive_failures", "Failed polls in a row.", Gauge},
		{"oob_server_last_success_timestamp_seconds", "Time of the last successful poll, Unix seconds.", Gauge},
		{"oob_server_poll_duration_seconds", "How long the last sensor poll took.", Gauge},
		{"oob_server_data_age_seconds", "Age of the cached sensor data.", Gauge},
		{"oob_server_health", "Health verdict (worst of the BMC rollup and every sensor; off while the host is powered " +
			"off and nothing is critical); 1 for the current state. Reported in maintenance too: combine with oob_server_maintenance.", Gauge},
		{"oob_server_power_state", "Host power state; 1 for the current state.", Gauge},
		{"oob_server_power_watts", "Chassis power draw, when the BMC reports it.", Gauge},
		{"oob_server_maintenance", "1 while the server is in maintenance mode (its health alerts are paused).", Gauge},
		{"oob_server_maintenance_until_timestamp_seconds", "End of the active maintenance window, Unix seconds; " +
			"0 when not in maintenance or when it lasts until it is ended.", Gauge},
		{"oob_server_bmc_restarting", "1 while the app waits for the server's BMC to come back after a restart it requested.", Gauge},
		{"oob_server_bmc_last_reset_timestamp_seconds", "Last BMC restart, Unix seconds: the BMC's own LastResetTime when it " +
			"reports one, else the app's last verified restart, else 0.", Gauge},
		{"oob_bmc_resets_total", "BMC restarts since start, by result (sent, refused, verified, timeout).", Counter},
		{"oob_fan_lease_active", "1 while a fan lease is active.", Gauge},
		{"oob_fan_lease_percent", "Fan floor requested by the active lease, percent.", Gauge},
		{"oob_fan_lease_remaining_seconds", "Time left on the active fan lease.", Gauge},
		{"oob_fan_applied_percent", "Fan floor the enforcing side reports as applied, percent.", Gauge},
		{"oob_log_entries", "Entries in the cached SEL or Lifecycle log, by severity.", Gauge},
		{"oob_events_unacknowledged", "Warning and critical entries of the cached logs that are not acknowledged.", Gauge},
		{"oob_security_checks", "BMC security check results of the last run, by result (pass, info, warn, fail, unknown, " +
			"cant-read, accepted). An accepted risk counts as accepted only.", Gauge},
		{"oob_tls_cert_expiry_timestamp_seconds", "Expiry of the BMC certificate on a port (HTTPS, and the VNC port " +
			"when the graphical console uses VNC over TLS and the port is probed: never on an iDRAC8), Unix seconds, from the last security check run.", Gauge},
		{"oob_firmware_components", "Firmware components of the server in the firmware view (its last scan).", Gauge},
		{"oob_firmware_flagged", "Firmware components with a flag, by flag (below_minimum, update_urgent, not_applied, " +
			"update_available, cannot_compare, stale_release). Versions are not exposed.", Gauge},
		{"oob_firmware_last_scan_timestamp_seconds", "When the server's firmware was last scanned, Unix seconds (0: never).", Gauge},
		{"oob_firmware_changes_total", "Firmware version changes seen since start.", Counter},
		{"oob_firmware_updates_available", "Firmware components with a newer vendor release that is not skipped, by the " +
			"release's criticality (urgent, recommended, optional). Versions are not exposed.", Gauge},
		{"oob_history_keys_refused_total", "Samples of new sensors the history refused since start (the server " +
			"reached its sensor limit: a BMC inventing sensor names), plus archived series deleted (a sensor changing " +
			"its unit or kind too often).", Counter},
	}
}

func sensorSpecs() []spec {
	return []spec{
		{"oob_temperature_celsius", "Temperature reading.", Gauge},
		{"oob_temperature_upper_warning_celsius", "Upper non-critical threshold of a temperature sensor.", Gauge},
		{"oob_temperature_upper_critical_celsius", "Upper critical threshold of a temperature sensor.", Gauge},
		{"oob_fan_speed_rpm", "Fan speed, for fans that report RPM.", Gauge},
		{"oob_fan_speed_percent", "Fan speed, for fans that report percent.", Gauge},
		{"oob_psu_healthy", "1 when the power supply reports OK health.", Gauge},
		{"oob_psu_input_watts", "Measured power supply input.", Gauge},
		{"oob_psu_redundant", "1 when at least two power supplies report OK health.", Gauge},
		{"oob_voltage_volts", "Voltage reading.", Gauge},
	}
}
