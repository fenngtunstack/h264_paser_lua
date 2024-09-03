-- Dump RTP h.265 payload to raw h.265 file (*.265)
-- According to RFC3984 to dissector H265 payload of RTP to NALU, and write it
-- to from<sourceIp_sourcePort>to<dstIp_dstPort>.265 file. By now, we support single NALU,
-- STAP-A and FU-A format RTP payload for H.265.
-- You can access this feature by menu "Tools->Export H265 to file [HQX's plugins]"
-- Author: Huang Qiangxiong (qiangxiong.huang@gmail.com)
-- change log:
--      2012-03-13
--          Just can play
--      2012-04-28
--          Add local to local function, and add [local bit = require("bit")] to prevent
--          bit recleared in previous file.
--      2013-07-11
--          Add sort RTP and drop uncompleted frame option.
--      2013-07-19
--          Do nothing when tap is triggered other than button event.
--          Add check for first or last packs lost of one frame.
--      2014-10-23
--          Fixed bug about print a frame.nalu_type error.
--      2014-11-07
--          Add support for Lua 5.2(>1.10.1) and 5.1(<=1.10.1).
--          Change range:string() to range:raw().
--          Change h265_f.value to h265_f.range:bytes() because of wireshark lua bug.
--      2015-06-03
--          Fixed bug that if ipv6 address is using the file will not generated.(we replace ':' to '.')
------------------------------------------------------------------------------------------------
do
    --local bit = require("bit") -- only work before 1.10.1
    --local bit = require("bit32") -- only work after 1.10.1 (only support in Lua 5.2)
	local version_str = string.match(_VERSION, "%d+[.]%d*")
	local version_num = version_str and tonumber(version_str) or 5.1
	--MediaStack local bit = (version_num >= 5.2) and require("bit32") or require("bit")

    -- for geting h265 data (the field's value is type of ByteArray)
    local f_h265 = Field.new("h265")
    local f_rtp = Field.new("rtp")
    local f_rtp_seq = Field.new("rtp.seq")
    local f_rtp_timestamp = Field.new("rtp.timestamp")
    local nalu_type_list = {
        [0] = "NAL_TRAIL_N",
        [1] = "NAL_TRAIL_R",
        [2] = "NAL_TSA_N",
        [3] = "NAL_TSA_R",
        [4] = "NAL_STSA_N",
        [5] = "NAL_STSA_R",
        [6] = "NAL_RADL_N",
		[7] = "NAL_RADL_R",
        [8] = "NAL_RASL_N",
        [9] = "NAL_RASL_R",
        [10] = "",
        [11] = "",
        [12] = "",
        [13] = "",
		[14] = "",
        [15] = "",
        [16] = "NAL_BLA_W_LP",
        [17] = "NAL_BLA_W_RADL",
        [18] = "NAL_BLA_N_LP",
        [19] = "NAL_IDR_W_RADL",
        [20] = "NAL_IDR_N_LP",
		[21] = "NAL_CRA_NUT",
        [22] = "",
        [23] = "",
        [24] = "",
		[25] = "",
        [26] = "",
        [27] = "",
        [28] = "",
        [29] = "",
        [30] = "",
		[31] = "",
		[32] = "NAL_VPS",
        [33] = "NAL_SPS",
        [34] = "NAL_PPS",
		[35] = "NAL_AUD",
        [36] = "NAL_EOS_NUT",
        [37] = "NAL_EOB_NUT",
        [38] = "NAL_FD_NUT",
        [39] = "NAL_SEI_PREFIX",
        [40] = "NAL_SEI_SUFFIX",
	}

    local function get_enum_name(list, index)
        local value = list[index]
        return value and value or "Unknown"
    end
	print("22222\n")
    -- menu action. When you click "Tools->Export H265 to file [HQX's plugins]" will run this function
    local function export_h265_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export H265 to File Info Win")
        --local pgtw = ProgDlg.new("Export H265 to File Process", "Dumping H265 data to file...")
        local pgtw;

        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end

        -- running first time for counting and finding vps+sps+pps, second time for real saving
        local first_run = true
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil
        -- drop_uncompleted_frame
        local drop_uncompleted_frame = false
        -- max frame buffer size
        local MAX_FRAME_NUM = 3

        -- trigered by all h265 packats
        local my_h265_tap = Listener.new(tap, "h265")

        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "to" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port) .. (drop_uncompleted_frame and "_dropped" or "_all")
			key = key:gsub(":", ".")
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".265"
                stream_info.file = io.open(stream_info.filename, "wb")
                stream_info.counter = 0 -- counting h265 total NALUs
                stream_info.counter2 = 0 -- for second time running
                stream_infos[key] = stream_info
                twappend("Ready to export H.265 data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " to file:\n         [" .. stream_info.filename .. "] ...\n")
            end
            return stream_info
        end

        -- write a NALU or part of NALU to file.
        local function real_write_to_file(stream_info, str_bytes, begin_with_nalu_hdr)
            if first_run then
                stream_info.counter = stream_info.counter + 1

                if begin_with_nalu_hdr then
                    -- save SPS or PPS
                    -- bit32 local nalu_type = bit.band(bit.rshift(str_bytes:byte(0,1),1), 0x3F)
					local nalu_type = (str_bytes:byte(0,1) >> 1) & 0x3F
                    if not stream_info.vps and nalu_type == 32 then
                        stream_info.vps = str_bytes
                    elseif not stream_info.sps and nalu_type == 33 then
                        stream_info.sps = str_bytes
                    elseif not stream_info.pps and nalu_type == 34 then
                        stream_info.pps = str_bytes
					end
                end

            else -- second time running
                --[[
                if begin_with_nalu_hdr then
                    -- drop AUD
                    local nalu_type = bit.band(str_bytes:byte(0,1), 0x1F)
                    if nalu_type == 9 then
                        return;
                    end
                end
                ]]

                if stream_info.counter2 == 0 then
                    -- write SPS and PPS to file header first
                    if stream_info.vps then
                        stream_info.file:write("\00\00\00\01")
                        stream_info.file:write(stream_info.vps)
                    else
                        twappend("Not found VPS for [" .. stream_info.filename .. "], it might not be played!\n")
                    end
                    if stream_info.sps then
                        stream_info.file:write("\00\00\00\01")
                        stream_info.file:write(stream_info.sps)
                    else
                        twappend("Not found SPS for [" .. stream_info.filename .. "], it might not be played!\n")
                    end
					    if stream_info.pps then
                        stream_info.file:write("\00\00\00\01")
                        stream_info.file:write(stream_info.pps)
                    else
                        twappend("Not found PPS for [" .. stream_info.filename .. "], it might not be played!\n")
                    end
                end

                if begin_with_nalu_hdr then
                    -- *.265 raw file format seams that every nalu start with 0x00000001
                    stream_info.file:write("\00\00\00\01")
                end
                stream_info.file:write(str_bytes)
                stream_info.counter2 = stream_info.counter2 + 1

                -- update progress window's progress bar
                if stream_info.counter > 0 and stream_info.counter2 < stream_info.counter then pgtw:update(stream_info.counter2 / stream_info.counter) end
            end
        end

        local function comp_pack(p1, p2)
            if math.abs(p2.seq - p1.seq) < 1000 then
                return p1.seq < p2.seq
            else -- seqeunce is over 2^16, so the small one is much big
                return p1.seq > p2.seq
            end
        end

        local function print_seq_error(stream_info, str)
            if stream_info.seq_error_counter == nil then
                stream_info.seq_error_counter = 0
            end
            stream_info.seq_error_counter = stream_info.seq_error_counter + 1
            twappend(str .. " SeqErrCounts=" .. stream_info.seq_error_counter)
        end

        local function sort_and_write(stream_info, frame)
            table.sort(frame.packs, comp_pack)

            -- check if it is uncompleted frame
            local completed = true
            for i = 1, #frame.packs - 1, 1 do
                local seq1 = frame.packs[i].seq
                local seq2 = frame.packs[i+1].seq
                -- MediaStack if bit.band(seq1+1, 0xFFFF) ~= seq2 then
				if (seq1+1 & 0xFFFF) ~= seq2 then
                    print_seq_error(stream_info, " RTP pack Lost: timestamp=" .. frame.timestamp .. " seq between " .. seq1 .. " and " .. seq2)
                    completed = false
                end
            end

            if not frame.packs[1].nalu_begin then
                print_seq_error(stream_info, " RTP pack Lost: timestamp=" .. frame.timestamp .. " seq before " .. frame.packs[1].seq)
                completed = false
            end

            if not frame.packs[#frame.packs].nalu_end then
                print_seq_error(stream_info, " RTP pack Lost: timestamp=" .. frame.timestamp .. " seq after " .. frame.packs[#frame.packs].seq)
                completed = false
            end

            if completed then
                for i = 1, #frame.packs, 1 do
                    real_write_to_file(stream_info, frame.packs[i].data, frame.packs[i].nalu_begin)
                end
            else
                twappend("   We drop one uncompleted frame: rtp.timestamp=" .. frame.timestamp
                         .. " nalu_type=" .. (frame.nalu_type and frame.nalu_type .."(" .. get_enum_name(nalu_type_list, frame.nalu_type) .. ")" or "unknown") )
            end
        end

        local function write_to_file(stream_info, str_bytes, begin_with_nalu_hdr, timestamp, seq, end_of_nalu)
            if drop_uncompleted_frame and not first_run then -- sort and drop uncompleted frame
				print("WWWWWWWWWWWWWWWWWWWWW\n")
                if stream_info.frame_buffer_size == nil then
                    stream_info.frame_buffer_size = 0
                end

                if timestamp < 0 or seq < 0 then
                    twappend(" Invalid rtp timestamp (".. timestamp .. ") or seq (".. seq .. ")! We have to write it to file directly!")
                    real_write_to_file(stream_info, str_bytes, begin_with_nalu_hdr)
                    return;
                end

                -- check if this frame has existed
                local p = stream_info.frame_buffer
                while p do
                    if p.timestamp == timestamp then
                        break;
                    else
                        p = p.next
                    end
                end

                if p then  -- add this pack to frame
                    if begin_with_nalu_hdr then
                        --p.nalu_type = bit.band(str_bytes:byte(1), 0x1F)
						-- MediaStack p.nalu_type = bit.band(bit.rshift(str_bytes:byte(0,1),1), 0x3F)
						p.nalu_type = (str_bytes:byte(0,1) >> 1) & 0x3F

                    end
                    table.insert(p.packs, { ["seq"] = seq, ["data"] = str_bytes , ["nalu_begin"] = begin_with_nalu_hdr, ["nalu_end"] = end_of_nalu })
                    return
                end

                if stream_info.frame_buffer_size >= MAX_FRAME_NUM then
                    -- write the most early frame to file
                    sort_and_write(stream_info, stream_info.frame_buffer)
                    stream_info.frame_buffer = stream_info.frame_buffer.next
                    stream_info.frame_buffer_size = stream_info.frame_buffer_size - 1
                end

                -- create a new frame buffer for new frame (timestamp)
                local frame = {}
                frame.timestamp = timestamp
                if begin_with_nalu_hdr then
                    --frame.nalu_type = bit.band(str_bytes:byte(1), 0x1F)
					-- MediaStack frame.nalu_type = bit.band(bit.rshift(str_bytes:byte(0,1),1), 0x3F)
					frame.nalu_type = (str_bytes:byte(0,1) >> 1) & 0x3F
                end
                frame.packs = {{ ["seq"] = seq, ["data"] = str_bytes, ["nalu_begin"] = begin_with_nalu_hdr, ["nalu_end"] = end_of_nalu}}  -- put pack to index 1 pos
                frame.next = nil

                if stream_info.frame_buffer_size == 0 then  -- first frame
                    stream_info.frame_buffer = frame
                else
                    p = stream_info.frame_buffer
                    while p.next do
                        p = p.next
                    end
                    p.next = frame
                end
                stream_info.frame_buffer_size = stream_info.frame_buffer_size + 1
            else -- write data direct to file without sort or frame drop
                real_write_to_file(stream_info, str_bytes, begin_with_nalu_hdr)
            end
        end

        -- read RFC3984 about single nalu/stap-a/fu-a H265 payload format of rtp
        -- single NALU: one rtp payload contains only NALU
        local function process_single_nalu(stream_info, h265, timestamp, seq)
            --write_to_file(stream_info, h265:tvb()():string(), true, timestamp, seq, true)
			write_to_file(stream_info, ((version_num >= 5.2) and h265:tvb():raw() or h265:tvb()():string()), true, timestamp, seq, true)
        end

        -- STAP-A: one rtp payload contains more than one NALUs
        local function process_stap_a(stream_info, h265, timestamp, seq)
			twappend("strp--------------------\n")
            local h265tvb = h265:tvb()
            local offset = 2
            local i = 1
            repeat
                local size = h265tvb(offset,3):uint()
                --write_to_file(stream_info, h265tvb(offset+2, size):string(), true, timestamp, i, true)
				write_to_file(stream_info, ((version_num >= 5.2) and h265tvb:raw(offset+3, size) or h265tvb(offset+3, size):string()), true, timestamp, i, true)
                offset = offset + 3 + size
                i = i + 1
            until offset >= h265tvb:len()
        end

        -- FU-A: one rtp payload contains only one part of a NALU (might be begin, middle and end part of a NALU)
        local function process_fu_a(stream_info, h265, timestamp, seq)
            local h265tvb = h265:tvb()
            local fu_idr1 = h265:get_index(0)
            local fu_idr2 = h265:get_index(1)
            local fu_hdr = h265:get_index(2)
			-- MediaStack local start_of_nalu =  (bit.band(fu_hdr, 0x80) ~= 0)
            -- MediaStack local end_of_nalu   =  (bit.band(fu_hdr, 0x40) ~= 0)
			local start_of_nalu =  (fu_hdr & 0x80) ~= 0
			local end_of_nalu   =  (fu_hdr & 0x40) ~= 0
            if start_of_nalu then
                -- start bit is set then save nalu header and body
				-- MediaStack local nalu_futype = bit.lshift(bit.band(fu_hdr, 0x3F),1)
                -- MediaStack local nalu_hdr1 = bit.bor(bit.band(fu_idr1, 0x81), nalu_futype)
				local nalu_futype = (fu_hdr & 0x3F) << 1
				local nalu_hdr1 = (fu_idr1 & 0x81) | nalu_futype
				
				local nalu_hdr2 = fu_idr2
                --write_to_file(stream_info, string.char(nalu_hdr) .. h265tvb(2):string(), true, timestamp, seq, end_of_nalu)
				write_to_file(stream_info, string.char(nalu_hdr1) ..  string.char(nalu_hdr2) .. ((version_num >= 5.2) and h265tvb:raw(3) or h265tvb(3):string()), true, timestamp, seq, end_of_nalu)
            	--write_to_file(stream_info, string.char(nalu_hdr2) .. ((version_num >= 5.2) and h265tvb:raw(3) or h265tvb(3):string()), false, timestamp, seq, end_of_nalu)
			else
                -- start bit not set, just write part of nalu body
                --write_to_file(stream_info, h265tvb(2):string(), false, timestamp, seq, end_of_nalu)
				write_to_file(stream_info, ((version_num >= 5.2) and h265tvb:raw(3) or h265tvb(3):string()), false, timestamp, seq, end_of_nalu)
            end
        end

        -- call this function if a packet contains h265 payload
        function my_h265_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local h265s = { f_h265() } -- using table because one packet may contains more than one RTP
            local rtps = { f_rtp() }
            local rtp_seqs = { f_rtp_seq() }
            local rtp_timestamps = { f_rtp_timestamp() }
            for i,h265_f in ipairs(h265s) do
                if h265_f.len < 2 then
                    return
                end
                --local h265 = h265_f.value   -- is ByteArray, it only works for 1.10.1 or early version
				--local h265 = h265_f.range:bytes()   -- according to user-guide.chm, there is a bug of fieldInfo.value, so we have to convert it to TVB range first
				local h265 = (version_num >= 5.2) and h265_f.range:bytes() or h265_f.value
                -- MediaStack local hdr_type = bit.band(bit.rshift(h265:get_index(0),1), 0x3F)
				local hdr_type = (h265:get_index(0) >> 1) & 0x3F
				twappend(string.format("hdr_type=%X %d", hdr_type, hdr_type))
                local stream_info = get_stream_info(pinfo)
--twappend("bytearray=" .. tostring(h265))
--twappend("byterange=" .. tostring(h265_f.range):upper())
                -- search the RTP timestamp and sequence of this H265
                local timestamp = -1
                local seq = -1
				-- debug begin
				local rtplen = -1
				local preh265_foffset = -1
				local prertp_foffset = -1
				local preh265len = -1
				-- debug end
                if drop_uncompleted_frame then
					local matchx = 0;
                    for j,rtp_f in ipairs(rtps) do
                        if h265_f.offset > rtp_f.offset and h265_f.offset - rtp_f.offset <= 16 and h265_f.offset+h265_f.len <= rtp_f.offset+rtp_f.len then
						-- debug begin
						--if h265_f.offset > rtp_f.offset and h265_f.offset < rtp_f.offset+rtp_f.len then
					matchx = matchx + 1
					if matchx > 1 then
						print_seq_error(stream_info, "ASS seq=" .. seq .. " timestamp=" .. timestamp .. " rtplen=" .. rtplen .. " rtpoff=" .. prertp_foffset .. " h265off=" .. preh265_foffset .. " h265len=" .. preh265len .. "  |matched=" .. matchx .. "  New seq=" .. rtp_seqs[j].value .. " timestamp=" .. rtp_timestamps[j].value .. " rtplen=" .. rtp_f.len .." rtpoff=" .. rtp_f.offset .. " h265off=" .. h265_f.offset .. " h265.len=" .. h265_f.len)
					end
					-- debug end
                            seq = rtp_seqs[j].value
                            timestamp = rtp_timestamps[j].value
							-- debug begin
							rtplen = rtp_f.len
							preh265_foffset = h265_f.offset
							prertp_foffset = rtp_f.offset
							preh265len = h265_f.len
							-- debug end
							twappend(" test321321321 (".. timestamp .. ") or seq (".. seq .. ")! We have to write it to file directly!")
							break
                        end
                    end

                end

                --if hdr_type == 32 or hdr_type == 33 or hdr_type == 34 then
				if hdr_type > 0 and hdr_type < 48 then
                    -- Single NALU
                    process_single_nalu(stream_info, h265, timestamp, seq)
                elseif hdr_type == 48 then
                    -- STAP-A Single-time aggregation
                   process_stap_a(stream_info, h265, timestamp, seq)
                elseif hdr_type == 49 then
                    -- FU-A
                    process_fu_a(stream_info, h265, timestamp, seq)
                else
                    twappend("Error: unknown type=" .. hdr_type .. " ; we only know 32 33 34(Single NALU),48(STAP-A),49(FU-A)!")
                end
            end
        end

        -- close all open files
        local function close_all_files()
            if stream_infos then
                local no_streams = true
                for id,stream in pairs(stream_infos) do
                    if stream and stream.file then
                        if stream.frame_buffer then
                            local p = stream.frame_buffer
                            while p do
                                sort_and_write(stream, p)
                                p = p.next
                            end
                            stream.frame_buffer = nil
                            stream.frame_buffer_size = 0
                        end
                        stream.file:flush()
                        stream.file:close()
                        twappend("File [" .. stream.filename .. "] generated OK!\n")
                        stream.file = nil
                        no_streams = false
                    end
                end

                if no_streams then
                    twappend("Not found any H.265 over RTP streams!")
                end
            end
        end

        function my_h265_tap.reset()
            -- do nothing now
        end

        local function remove()
            my_h265_tap:remove()
        end

        tw:set_atclose(remove)

        local function export_h265(drop_frame)
            pgtw = ProgDlg.new("Export H265 to File Process", "Dumping H265 data to file...")
            first_run = true
            drop_uncompleted_frame = drop_frame
            stream_infos = {}
            -- first time it runs for counting h.265 packets and finding SPS and PPS
            retap_packets()--my_h265_tap.packet
            first_run = false
            -- second time it runs for saving h265 data to target file.
            retap_packets()
            close_all_files()
            -- close progress window
            pgtw:close()
            stream_infos = nil
        end

        local function export_all()
            export_h265(false)
        end

        local function export_completed_frames()
            export_h265(true)
        end

        tw:add_button("Export All", export_all)
        tw:add_button("Export Completed Frames (Drop uncompleted frames)", export_completed_frames)
    end

    -- Find this feature in menu "Tools->"Export H265 to file [HQX's plugins]""
    register_menu("Export H265 to file [HQX's plugins]", export_h265_to_file, MENU_TOOLS_UNSORTED)
end