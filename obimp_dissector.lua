p_obimp = Proto("obimp", "OBIMP Protocol")

-- BEX type
bexTypes = { [1] = "OBIMP_BEX_COM", "OBIMP_BEX_CL", "OBIMP_BEX_PRES", "OBIMP_BEX_IM", "OBIMP_BEX_UD", "OBIMP_BEX_UA", "OBIMP_BEX_FT", "OBIMP_BEX_TP", [0xF001] = "OBIMP_BEX_WADM" }

-- BEX subtype
OBIMP_BEX_COM = { [1] = "CLI_HELLO", "SRV_HELLO", "CLI_LOGIN", "SRV_LOGIN_REPLY", "SRV_BYE", "CLI_SRV_KEEPALIVE_PING", "CLI_SRV_KEEPALIVE_PONG", "CLI_REGISTER", "SRV_REGISTER_REPLY" }
OBIMP_BEX_CL = { [1] = "CLI_PARAMS", "SRV_PARAMS_REPLY", "CLI_REQUEST", "SRV_REPLY", "CLI_VERIFY", "SRV_VERIFY_REPLY", "CLI_ADD_ITEM", "SRV_ADD_ITEM_REPLY", "CLI_DEL_ITEM", "SRV_DEL_ITEM_REPLY", "CLI_UPD_ITEM", "SRV_UPD_ITEM_REPLY", "CLI_SRV_AUTH_REQUEST", "CLI_SRV_AUTH_REPLY", "CLI_SRV_AUTH_REVOKE", "CLI_REQ_OFFAUTH", "SRV_DONE_OFFAUTH", "CLI_DEL_OFFAUTH", "SRV_ITEM_OPER","SRV_BEGIN_UPDATE","SRV_END_UPDATE" }
OBIMP_BEX_PRES = { [1] = "CLI_PARAMS", "SRV_PARAMS_REPLY", "CLI_SET_PRES_INFO", "CLI_SET_STATUS", "CLI_ACTIVATE", "SRV_CONTACT_ONLINE", "SRV_CONTACT_OFFLINE", "CLI_REQ_PRES_INFO", "SRV_PRES_INFO", "SRV_MAIL_NOTIF", "CLI_REQ_OWN_MAIL_URL", "SRV_OWN_MAIL_URL" }
OBIMP_BEX_IM = { [1] = "CLI_PARAMS", "SRV_PARAMS_REPLY", "CLI_REQ_OFFLINE", "SRV_DONE_OFFLINE", "CLI_DEL_OFFLINE", "CLI_MESSAGE", "SRV_MESSAGE", "CLI_SRV_MSG_REPORT", "CLI_SRV_NOTIFY", "CLI_SRV_ENCRYPT_KEY_REQ", "CLI_SRV_ENCRYPT_KEY_REPLY", "CLI_MULTIPLE_MSG" }
OBIMP_BEX_UD = { [1] = "CLI_PARAMS", "SRV_PARAMS_REPLY", "CLI_DETAILS_REQ", "SRV_DETAILS_REQ_REPLY", "CLI_DETAILS_UPD", "SRV_DETAILS_UPD_REPLY", "CLI_SEARCH", "SRV_SEARCH_REPLY", "CLI_SECURE_UPD", "SRV_SECURE_UPD_REPLY" }
OBIMP_BEX_UA = { [1] = "CLI_PARAMS", "SRV_PARAMS_REPLY", "CLI_AVATAR_REQ", "SRV_AVATAR_REPLY", "CLI_AVATAR_SET", "SRV_AVATAR_SET_REPLY" }
OBIMP_BEX_FT = { [1] = "CLI_PARAMS", "SRV_PARAMS_REPLY", "CLI_SRV_SEND_FILE_REQUEST", "CLI_SRV_SEND_FILE_REPLY", "CLI_SRV_CONTROL", [0x0101] = "DIR_PROX_ERROR", "DIR_PROX_HELLO", "DIR_PROX_FILE", "DIR_PROX_FILE_REPLY", "DIR_PROX_FILE_DATA" }
OBIMP_BEX_TP = { [1] = "CLI_PARAMS", "SRV_PARAMS_REPLY", "SRV_ITEM_READY", "CLI_SETTINGS", "SRV_SETTINGS_REPLY", "CLI_MANAGE", "SRV_TRANSPORT_INFO", "SRV_SHOW_NOTIF", "SRV_OWN_AVATAR_HASH" }
--  Windows server administration
OBIMP_BEX_WADM = { [1] = "CLI_LOGIN", "SRV_LOGIN_REPLY", "CLI_PARAMS", "SRV_PARAMS_REPLY", "CLI_SET", "SRV_SET_REPLY", "CLI_BROADCAST", "SRV_BROADCAST_REPLY", "CLI_USER", "SRV_USER_REPLY", "SRV_STATE", "CLI_LIST", "SRV_LIST_REPLY", "CLI_EXT_LIST_REQ", "SRV_EXT_LIST_REPLY", "CLI_EXT_UPD", "SRV_EXT_UPD_REPLY" }

function p_obimp_subtype(otype, subtype)
	if otype == 1 then
	  return OBIMP_BEX_COM[subtype]
	elseif otype == 2 then
	  return OBIMP_BEX_CL[subtype]
	elseif otype == 3 then
	  return OBIMP_BEX_PRES[subtype]
	elseif otype == 4 then
	  return OBIMP_BEX_IM[subtype]
	elseif otype == 5 then
	  return OBIMP_BEX_UD[subtype]
	elseif otype == 6 then
	  return OBIMP_BEX_UA[subtype]
	elseif otype == 7 then
	  return OBIMP_BEX_FT[subtype]
	elseif otype == 8 then
	  return OBIMP_BEX_TP[subtype]
	elseif otype == 0xF001 then
	  return OBIMP_BEX_WADM[subtype]
	else
	  return ""
	end
end

-- Header
local f_hdr_sign = ProtoField.uint8("obimp.hdr.sign", "Sign", base.HEX)
local f_hdr_sequence = ProtoField.uint32("obimp.hdr.sequence", "Sequence", base.DEC)
local f_hdr_type = ProtoField.uint16("obimp.hdr.type", "Type", base.HEX, bexTypes)
local f_hdr_subtype = ProtoField.uint16("obimp.hdr.subtype", "Subtype", base.HEX)
local f_hdr_request_id = ProtoField.uint32("obimp.hdr.request_id", "RequestId", base.DEC)

-- Len payload & payload data
local f_pl_len = ProtoField.uint32("obimp.pl_len", "Payload Length")
local f_payload = ProtoField.bytes("obimp.payload", "Payload", base.BYTES)

p_obimp.fields = { f_hdr_sign, f_hdr_sequence, f_hdr_type, f_hdr_subtype, f_hdr_request_id, f_pl_len, f_payload }

function p_obimp.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end
	
	local pktlen = buf:reported_length_remaining()
	local pos = 0
	local bexCount = 0
	local bex_types = {}
	
	pinfo.cols.protocol = p_obimp.name
	obimp_root = tree:add(p_obimp)

    while pos < pktlen do
	
		local sign = buf(pos,1):uint()
		
		if sign == 35 then
			bexCount = bexCount + 1
			local type_str = bexTypes[buf(pos + 5, 2):uint()]
			if type_str == nil then type_str = "Unknown" end
			table.insert(bex_types, type_str)
			local s_stype = p_obimp_subtype(buf(pos + 5, 2):uint(), buf(pos + 7, 2):uint())

			subtree = obimp_root:add(string.format("BEX type: %s subtype: %s", type_str, s_stype))

			subtree:add(f_hdr_sequence, buf(pos + 1, 4))
			subtree:add(f_hdr_type, buf(pos + 5, 2))
			local subtype = buf(pos + 7, 2):uint()
			subtree:add(f_hdr_subtype, subtype)
				   :set_text(string.format("Subtype: %s (0x%04x)", s_stype, subtype))
			subtree:add(f_hdr_request_id, buf(pos + 9, 4))
			subtree:add(f_pl_len, buf(pos + 13,4))

			-- len payload
			local pl_len = buf(pos + 13,4):uint()
			if pl_len == 0 then 
				pos = pos + 17
			else
				subtree:add(f_payload, buf(pos + 17, pl_len))  -- payload
				pos = pos + 17 + pl_len
			end
		else
			subtree:append_text(string.format(", invalid signature of OBIMP protocol (0x%02x)", sign))
		end
    end
	-- в колонке Info будет отображаться тип(ы) пакета(ов)
	pinfo.cols.info = string.format("Bex(%d):[ %s ]", bexCount, table.concat(bex_types, ", "))
end

-- регистрируем диссектор на TCP порт 7023, 7024, 7025
do
	local tcp_port_table = DissectorTable.get("tcp.port")
	for i,port in ipairs{7023,7024,7025} do
		tcp_port_table:add(port, p_obimp)
	end
end
