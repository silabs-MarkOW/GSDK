#! /bin/env python3

import sys
bg_err = {
  0x0501 : 'bg_err_hardware_ps_store_full',
  0x0502 : 'bg_err_hardware_ps_key_not_found',
  0x0503 : 'bg_err_hardware_i2c_ack_missing',
  0x0504 : 'bg_err_hardware_i2c_timeout',
  0x0000 : 'bg_err_success',
  0x0101 : 'bg_err_invalid_conn_handle',
  0x0102 : 'bg_err_waiting_response',
  0x0103 : 'bg_err_gatt_connection_timeout',
  0x0180 : 'bg_err_invalid_param',
  0x0181 : 'bg_err_wrong_state',
  0x0182 : 'bg_err_out_of_memory',
  0x0183 : 'bg_err_not_implemented',
  0x0184 : 'bg_err_invalid_command',
  0x0185 : 'bg_err_timeout',
  0x0186 : 'bg_err_not_connected',
  0x0187 : 'bg_err_flow',
  0x0188 : 'bg_err_user_attribute',
  0x0189 : 'bg_err_invalid_license_key',
  0x018a : 'bg_err_command_too_long',
  0x018b : 'bg_err_out_of_bonds',
  0x018c : 'bg_err_unspecified',
  0x018d : 'bg_err_hardware',
  0x018e : 'bg_err_buffers_full',
  0x018f : 'bg_err_disconnected',
  0x0190 : 'bg_err_too_many_requests',
  0x0191 : 'bg_err_not_supported',
  0x0192 : 'bg_err_no_bonding',
  0x0193 : 'bg_err_crypto',
  0x0194 : 'bg_err_data_corrupted',
  0x0195 : 'bg_err_command_incomplete',
  0x0196 : 'bg_err_not_initialized',
  0x0197 : 'bg_err_invalid_sync_handle',
  0x0198 : 'bg_err_invalid_module_action',
  0x0199 : 'bg_err_radio',
  0x0301 : 'bg_err_smp_passkey_entry_failed',
  0x0302 : 'bg_err_smp_oob_not_available',
  0x0303 : 'bg_err_smp_authentication_requirements',
  0x0304 : 'bg_err_smp_confirm_value_failed',
  0x0305 : 'bg_err_smp_pairing_not_supported',
  0x0306 : 'bg_err_smp_encryption_key_size',
  0x0307 : 'bg_err_smp_command_not_supported',
  0x0308 : 'bg_err_smp_unspecified_reason',
  0x0309 : 'bg_err_smp_repeated_attempts',
  0x030a : 'bg_err_smp_invalid_parameters',
  0x030b : 'bg_err_smp_dhkey_check_failed',
  0x030c : 'bg_err_smp_numeric_comparison_failed',
  0x030d : 'bg_err_smp_bredr_pairing_in_progress',
  0x030e : 'bg_err_smp_cross_transport_key_derivation_generation_not_allowed',
  0x0000 : 'bg_err_bt_error_success',
  0x0202 : 'bg_err_bt_unknown_connection_identifier',
  0x0205 : 'bg_err_bt_authentication_failure',
  0x0206 : 'bg_err_bt_pin_or_key_missing',
  0x0207 : 'bg_err_bt_memory_capacity_exceeded',
  0x0208 : 'bg_err_bt_connection_timeout',
  0x0209 : 'bg_err_bt_connection_limit_exceeded',
  0x020a : 'bg_err_bt_synchronous_connectiontion_limit_exceeded',
  0x020b : 'bg_err_bt_acl_connection_already_exists',
  0x020c : 'bg_err_bt_command_disallowed',
  0x020d : 'bg_err_bt_connection_rejected_due_to_limited_resources',
  0x020e : 'bg_err_bt_connection_rejected_due_to_security_reasons',
  0x020f : 'bg_err_bt_connection_rejected_due_to_unacceptable_bd_addr',
  0x0210 : 'bg_err_bt_connection_accept_timeout_exceeded',
  0x0211 : 'bg_err_bt_unsupported_feature_or_parameter_value',
  0x0212 : 'bg_err_bt_invalid_command_parameters',
  0x0213 : 'bg_err_bt_remote_user_terminated',
  0x0214 : 'bg_err_bt_remote_device_terminated_connection_due_to_low_resources',
  0x0215 : 'bg_err_bt_remote_powering_off',
  0x0216 : 'bg_err_bt_connection_terminated_by_local_host',
  0x0217 : 'bg_err_bt_repeated_attempts',
  0x0218 : 'bg_err_bt_pairing_not_allowed',
  0x021a : 'bg_err_bt_unsupported_remote_feature',
  0x021f : 'bg_err_bt_unspecified_error',
  0x0222 : 'bg_err_bt_ll_response_timeout',
  0x0223 : 'bg_err_bt_ll_procedure_collision',
  0x0225 : 'bg_err_bt_encryption_mode_not_acceptable',
  0x0226 : 'bg_err_bt_link_key_cannot_be_changed',
  0x0228 : 'bg_err_bt_instant_passed',
  0x0229 : 'bg_err_bt_pairing_with_unit_key_not_supported',
  0x022a : 'bg_err_bt_different_transaction_collision',
  0x022e : 'bg_err_bt_channel_assessment_not_supported',
  0x022f : 'bg_err_bt_insufficient_security',
  0x0230 : 'bg_err_bt_parameter_out_of_mandatory_range',
  0x0237 : 'bg_err_bt_simple_pairing_not_supported_by_host',
  0x0238 : 'bg_err_bt_host_busy_pairing',
  0x0239 : 'bg_err_bt_connection_rejected_due_to_no_suitable_channel_found',
  0x023a : 'bg_err_bt_controller_busy',
  0x023b : 'bg_err_bt_unacceptable_connection_interval',
  0x023c : 'bg_err_bt_advertising_timeout',
  0x023d : 'bg_err_bt_connection_terminated_due_to_mic_failure',
  0x023e : 'bg_err_bt_connection_failed_to_be_established',
  0x023f : 'bg_err_bt_mac_connection_failed',
  0x0240 : 'bg_err_bt_coarse_clock_adjustment_rejected_but_will_try_to_adjust_using_clock_dragging',
  0x0242 : 'bg_err_bt_unknown_advertising_identifier',
  0x0243 : 'bg_err_bt_limit_reached',
  0x0244 : 'bg_err_bt_operation_cancelled_by_host',
  0x0245 : 'bg_err_bt_packet_too_long',
  0x0a01 : 'bg_err_application_file_open_failed',
  0x0a02 : 'bg_err_application_xml_parse_failed',
  0x0a03 : 'bg_err_application_device_connection_failed',
  0x0a04 : 'bg_err_application_device_comunication_failed',
  0x0a05 : 'bg_err_application_authentication_failed',
  0x0a06 : 'bg_err_application_incorrect_gatt_database',
  0x0a07 : 'bg_err_application_disconnected_due_to_procedure_collision',
  0x0a08 : 'bg_err_application_disconnected_due_to_secure_session_failed',
  0x0a09 : 'bg_err_application_encryption_decryption_error',
  0x0a0a : 'bg_err_application_maximum_retries',
  0x0a0b : 'bg_err_application_data_parse_failed',
  0x0a0c : 'bg_err_application_pairing_removed',
  0x0a0d : 'bg_err_application_inactive_timeout',
  0x0a0e : 'bg_err_application_mismatched_or_insufficient_security',
  0x0401 : 'bg_err_att_invalid_handle',
  0x0402 : 'bg_err_att_read_not_permitted',
  0x0403 : 'bg_err_att_write_not_permitted',
  0x0404 : 'bg_err_att_invalid_pdu',
  0x0405 : 'bg_err_att_insufficient_authentication',
  0x0406 : 'bg_err_att_request_not_supported',
  0x0407 : 'bg_err_att_invalid_offset',
  0x0408 : 'bg_err_att_insufficient_authorization',
  0x0409 : 'bg_err_att_prepare_queue_full',
  0x040a : 'bg_err_att_att_not_found',
  0x040b : 'bg_err_att_att_not_long',
  0x040c : 'bg_err_att_insufficient_enc_key_size',
  0x040d : 'bg_err_att_invalid_att_length',
  0x040e : 'bg_err_att_unlikely_error',
  0x040f : 'bg_err_att_insufficient_encryption',
  0x0410 : 'bg_err_att_unsupported_group_type',
  0x0411 : 'bg_err_att_insufficient_resources',
  0x0412 : 'bg_err_att_out_of_sync',
  0x0413 : 'bg_err_att_value_not_allowed',
  0x0480 : 'bg_err_att_application',
  0x0c01 : 'bg_err_mesh_already_exists',
  0x0c02 : 'bg_err_mesh_does_not_exist',
  0x0c03 : 'bg_err_mesh_limit_reached',
  0x0c04 : 'bg_err_mesh_invalid_address',
  0x0c05 : 'bg_err_mesh_malformed_data',
  0x0c06 : 'bg_err_mesh_already_initialized',
  0x0c07 : 'bg_err_mesh_not_initialized',
  0x0c08 : 'bg_err_mesh_no_friend_offer',
  0x0c09 : 'bg_err_mesh_prov_link_closed',
  0x0c0a : 'bg_err_mesh_prov_invalid_pdu',
  0x0c0b : 'bg_err_mesh_prov_invalid_pdu_format',
  0x0c0c : 'bg_err_mesh_prov_unexpected_pdu',
  0x0c0d : 'bg_err_mesh_prov_confirmation_failed',
  0x0c0e : 'bg_err_mesh_prov_out_of_resources',
  0x0c0f : 'bg_err_mesh_prov_decryption_failed',
  0x0c10 : 'bg_err_mesh_prov_unexpected_error',
  0x0c11 : 'bg_err_mesh_prov_cannot_assign_addr',
  0x0c12 : 'bg_err_mesh_address_temporarily_unavailable',
  0x0c13 : 'bg_err_mesh_address_already_used',
  0x0c14 : 'bg_err_mesh_no_data_available',
  0x0e01 : 'bg_err_mesh_foundation_invalid_address',
  0x0e02 : 'bg_err_mesh_foundation_invalid_model',
  0x0e03 : 'bg_err_mesh_foundation_invalid_app_key',
  0x0e04 : 'bg_err_mesh_foundation_invalid_net_key',
  0x0e05 : 'bg_err_mesh_foundation_insufficient_resources',
  0x0e06 : 'bg_err_mesh_foundation_key_index_exists',
  0x0e07 : 'bg_err_mesh_foundation_invalid_publish_params',
  0x0e08 : 'bg_err_mesh_foundation_not_subscribe_model',
  0x0e09 : 'bg_err_mesh_foundation_storage_failure',
  0x0e0a : 'bg_err_mesh_foundation_not_supported',
  0x0e0b : 'bg_err_mesh_foundation_cannot_update',
  0x0e0c : 'bg_err_mesh_foundation_cannot_remove',
  0x0e0d : 'bg_err_mesh_foundation_cannot_bind',
  0x0e0e : 'bg_err_mesh_foundation_temporarily_unable',
  0x0e0f : 'bg_err_mesh_foundation_cannot_set',
  0x0e10 : 'bg_err_mesh_foundation_unspecified',
  0x0e11 : 'bg_err_mesh_foundation_invalid_binding',
  0x0901 : 'bg_err_filesystem_file_not_found',
  0x0d01 : 'bg_err_l2cap_remote_disconnected',
  0x0d02 : 'bg_err_l2cap_local_disconnected',
  0x0d03 : 'bg_err_l2cap_cid_not_exist',
  0x0d04 : 'bg_err_l2cap_le_disconnected',
  0x0d05 : 'bg_err_l2cap_flow_control_violated',
  0x0d06 : 'bg_err_l2cap_flow_control_credit_overflowed',
  0x0d07 : 'bg_err_l2cap_no_flow_control_credit',
  0x0d08 : 'bg_err_l2cap_connection_request_timeout',
  0x0d09 : 'bg_err_l2cap_invalid_cid',
  0x0d0a : 'bg_err_l2cap_wrong_state',
  0x0b01 : 'bg_err_security_image_signature_verification_failed',
  0x0b02 : 'bg_err_security_file_signature_verification_failed',
  0x0b03 : 'bg_err_security_image_checksum_error',
  0x0b04 : 'bg_err_last'}

if __name__ == '__main__' :
    argv = sys.argv
    argc = len(argv)
    if argc < 2 :
        print('Usage %s errorcode [ errorcode [ ... ] ]'%(argv[0]))
        quit()
    for ec in argv[1:] :
        if len(ec) > 2 and ec.lower()[:2] == '0x' :
            ec = int(ec[2:],16)
        else :
            ec = int(ec)
        name = bg_err.get(ec)
        if None == name : name = '*UNKNOWN*'
        print('%04x: %s'%(ec,name))
