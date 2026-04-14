-- Dump RTP MP4V-ES payload to raw MPEG-4 Visual file (*.m4v)
-- According to RFC 6416, MP4V-ES over RTP directly maps MPEG-4 Visual bitstream
-- onto RTP payload without extra header fields. VOPs may be fragmented at arbitrary
-- byte positions. RTP marker bit indicates the last packet of a VOP.
-- You can access this feature by menu "Tools->Export MP4V-ES to file [Fenngtun's plugins]"
-- Based on h264-lua53.lua / h265-lua53.lua by Fenngtun
-- Adapted for MP4V-ES by pcaptools
-- change log:
--      2026-04-14
--          Initial version for MP4V-ES (MPEG-4 Visual) over RTP export
--      2026-04-14
--          Fix: auto-detect SDP out-of-band config when VOS/VO/VOL not in RTP stream
------------------------------------------------------------------------------------------------
do
    local version_str = string.match(_VERSION, "%d+[.]%d*")
    local version_num = version_str and tonumber(version_str) or 5.1

    -- for getting mp4ves data (the field's value is type of ByteArray)
    -- Wireshark protocol name is "mp4v-es" (with hyphen), field prefix is "mp4ves"
    local f_mp4ves = Field.new("mp4v-es")
    local f_rtp = Field.new("rtp")
    local f_rtp_seq = Field.new("rtp.seq")
    local f_rtp_timestamp = Field.new("rtp.timestamp")
    local f_rtp_marker = Field.new("rtp.marker")

    -- try to get configuration from Wireshark dissector (may not be available)
    local f_mp4ves_config = nil
    pcall(function() f_mp4ves_config = Field.new("mp4ves.configuration") end)

    -- SDP fmtp parameter field (contains config=... for MP4V-ES)
    local f_sdp_fmtp_param = nil
    pcall(function() f_sdp_fmtp_param = Field.new("sdp.fmtp.parameter") end)

    -- menu action. When you click "Tools->Export MP4V-ES to file [Fenton's plugins]" will run this function
    local function export_mp4ves_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export MP4V-ES to File Info Win")
        local pgtw;

        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end

        -- running first time for counting and finding VOS+VO+VOL, second time for real saving
        local first_run = true
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil
        -- drop_uncompleted_frame
        local drop_uncompleted_frame = false
        -- max frame buffer size
        local MAX_FRAME_NUM = 3
        -- cached SDP config extracted from Wireshark dissector
        local cached_config_bytes = nil

        -- triggered by all packets (we need SDP packets too for config extraction)
        -- We filter mp4v-es packets inside the callback manually
        local my_mp4ves_tap = Listener.new(tap)

        -- convert hex string to binary string
        local function hex_to_bytes(hex)
            return (hex:gsub("..", function(cc)
                return string.char(tonumber(cc, 16))
            end))
        end

        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port)
                           .. "to" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
                           .. (drop_uncompleted_frame and "_dropped" or "_all")
            key = key:gsub(":", ".")
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".m4v"
                stream_info.file = io.open(stream_info.filename, "wb")
                stream_info.counter = 0 -- counting mp4ves total packets
                stream_info.counter2 = 0 -- for second time running
                stream_infos[key] = stream_info
                twappend("Ready to export MP4V-ES data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " to file:\n         ["
                         .. stream_info.filename .. "] ...\n")
            end
            return stream_info
        end

        -- write data to file.
        local function real_write_to_file(stream_info, str_bytes, is_vop_start)
            if first_run then
                stream_info.counter = stream_info.counter + 1

                -- detect and save configuration headers (VOS, VO, VOL) during first run
                if is_vop_start then
                    -- str_bytes is a Lua string (1-based indexing)
                    local byte3 = str_bytes:byte(3)   -- should be 0x01
                    local byte4 = str_bytes:byte(4)   -- the start code type byte

                    if byte3 == 0x01 and byte4 ~= nil then
                        local sc = byte4
                        -- VOS: 00 00 01 B0
                        if sc == 0xB0 and not stream_info.vos then
                            stream_info.vos = str_bytes
                            twappend("  Found VOS in RTP stream")
                        -- VO: 00 00 01 B5
                        elseif sc == 0xB5 and not stream_info.vo then
                            stream_info.vo = str_bytes
                            twappend("  Found VO in RTP stream")
                        -- VOL: 00 00 01 20-2F
                        elseif sc >= 0x20 and sc <= 0x2F and not stream_info.vol then
                            stream_info.vol = str_bytes
                            twappend("  Found VOL in RTP stream")
                        end
                    end
                end

            else -- second time running
                if stream_info.counter2 == 0 then
                    -- write configuration headers to file first
                    -- priority: RTP stream embedded > Wireshark dissector config
                    local has_config = false

                    if stream_info.vos then
                        stream_info.file:write(stream_info.vos)
                        has_config = true
                    end
                    if stream_info.vo then
                        stream_info.file:write(stream_info.vo)
                        has_config = true
                    end
                    if stream_info.vol then
                        stream_info.file:write(stream_info.vol)
                        has_config = true
                    end

                    if not has_config and cached_config_bytes then
                        -- use config extracted from Wireshark mp4ves.configuration field
                        stream_info.file:write(cached_config_bytes)
                        twappend("  Config headers written from Wireshark dissector (" .. #cached_config_bytes .. " bytes)")
                        has_config = true
                    end

                    if not has_config then
                        twappend("WARNING: No VOS/VO/VOL config found for [" .. stream_info.filename .. "]!")
                        twappend("  The output file may not play correctly.")
                        twappend("  Config may be in SDP only (a=fmtp:.. config=<hex>). Check SIP/SDP packets.")
                    end
                end

                stream_info.file:write(str_bytes)
                stream_info.counter2 = stream_info.counter2 + 1
                -- update progress window's progress bar
                if stream_info.counter > 0 and stream_info.counter2 < stream_info.counter then
                    pgtw:update(stream_info.counter2 / stream_info.counter)
                end
            end
        end

        local function comp_pack(p1, p2)
            if math.abs(p2.seq - p1.seq) < 1000 then
                return p1.seq < p2.seq
            else -- sequence is over 2^16, so the small one is much big
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
                if (seq1+1 & 0xFFFF) ~= seq2 then
                    print_seq_error(stream_info, " RTP pack Lost: timestamp=" .. frame.timestamp .. " seq between " .. seq1 .. " and " .. seq2)
                    completed = false
                end
            end

            -- first packet must be a VOP start (or config start)
            if not frame.packs[1].is_start then
                print_seq_error(stream_info, " RTP pack Lost: timestamp=" .. frame.timestamp .. " first packet is not VOP start, seq=" .. frame.packs[1].seq)
                completed = false
            end

            -- last packet must have marker bit set (VOP end)
            if not frame.packs[#frame.packs].is_end then
                print_seq_error(stream_info, " RTP pack Lost: timestamp=" .. frame.timestamp .. " last packet missing marker bit, seq=" .. frame.packs[#frame.packs].seq)
                completed = false
            end

            if completed then
                for i = 1, #frame.packs, 1 do
                    real_write_to_file(stream_info, frame.packs[i].data, frame.packs[i].is_start)
                end
            else
                twappend("   We drop one uncompleted frame: rtp.timestamp=" .. frame.timestamp)
            end
        end

        local function write_to_file(stream_info, str_bytes, is_vop_start, timestamp, seq, is_vop_end)
            if drop_uncompleted_frame and not first_run then -- sort and drop uncompleted frame
                if stream_info.frame_buffer_size == nil then
                    stream_info.frame_buffer_size = 0
                end

                if timestamp < 0 or seq < 0 then
                    twappend(" Invalid rtp timestamp (".. timestamp .. ") or seq (".. seq .. ")! We have to write it to file directly!")
                    real_write_to_file(stream_info, str_bytes, is_vop_start)
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
                    table.insert(p.packs, {
                        ["seq"] = seq,
                        ["data"] = str_bytes,
                        ["is_start"] = is_vop_start,
                        ["is_end"] = is_vop_end
                    })
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
                frame.packs = {{
                    ["seq"] = seq,
                    ["data"] = str_bytes,
                    ["is_start"] = is_vop_start,
                    ["is_end"] = is_vop_end
                }}
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
                real_write_to_file(stream_info, str_bytes, is_vop_start)
            end
        end

        -- check if payload starts with a start code (00 00 01 xx)
        local function starts_with_start_code(data)
            if data:len() < 4 then
                return false
            end
            return data:get_index(0) == 0x00
               and data:get_index(1) == 0x00
               and data:get_index(2) == 0x01
        end

        -- call this function for every packet
        function my_mp4ves_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end

            -- during first run, try to extract config from SDP fmtp parameters
            if first_run and not cached_config_bytes and f_sdp_fmtp_param then
                local ok, fmtps = pcall(function() return { f_sdp_fmtp_param() } end)
                if ok and #fmtps > 0 then
                    for _, fmtp_f in ipairs(fmtps) do
                        local fmtp_str = tostring(fmtp_f.value)
                        local config_hex = fmtp_str:match("config=([0-9a-fA-F]+)")
                        if config_hex and #config_hex > 0 then
                            if #config_hex % 2 ~= 0 then
                                config_hex = "0" .. config_hex
                            end
                            cached_config_bytes = hex_to_bytes(config_hex)
                            twappend("  Found SDP config: " .. config_hex)
                            break
                        end
                    end
                end
            end

            -- check if this packet contains mp4v-es data
            local ok_mp4ves, mp4vess = pcall(function() return { f_mp4ves() } end)
            if not ok_mp4ves or #mp4vess == 0 then
                return -- not an mp4v-es packet, skip
            end
            local rtps = { f_rtp() }
            local rtp_seqs = { f_rtp_seq() }
            local rtp_timestamps = { f_rtp_timestamp() }
            local rtp_markers = { f_rtp_marker() }

            for i, mp4ves_f in ipairs(mp4vess) do
                if mp4ves_f.len < 1 then
                    return
                end
                local mp4ves = (version_num >= 5.2) and mp4ves_f.range:bytes() or mp4ves_f.value

                local stream_info = get_stream_info(pinfo)

                -- search the RTP timestamp, sequence and marker bit of this MP4V-ES packet
                local timestamp = -1
                local seq = -1
                local marker = false
                local is_vop_start = starts_with_start_code(mp4ves)

                if drop_uncompleted_frame then
                    for j,rtp_f in ipairs(rtps) do
                        if mp4ves_f.offset > rtp_f.offset
                           and mp4ves_f.offset - rtp_f.offset <= 16
                           and mp4ves_f.offset + mp4ves_f.len <= rtp_f.offset + rtp_f.len then
                            seq = rtp_seqs[j].value
                            timestamp = rtp_timestamps[j].value
                            marker = rtp_markers[j].value
                            break
                        end
                    end
                end

                -- get raw payload bytes
                local raw_bytes
                if version_num >= 5.2 then
                    raw_bytes = mp4ves:tvb():raw()
                else
                    raw_bytes = mp4ves:tvb()():string()
                end

                write_to_file(stream_info, raw_bytes, is_vop_start, timestamp, seq, marker)
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
                    twappend("Not found any MP4V-ES over RTP streams!")
                end
            end
        end

        function my_mp4ves_tap.reset()
            -- do nothing now
        end

        local function remove()
            my_mp4ves_tap:remove()
        end

        tw:set_atclose(remove)

        local function export_mp4ves(drop_frame)
            pgtw = ProgDlg.new("Export MP4V-ES to File Process", "Dumping MP4V-ES data to file...")
            first_run = true
            drop_uncompleted_frame = drop_frame
            stream_infos = {}
            cached_config_bytes = nil

            -- first pass: count packets, find VOS/VO/VOL, and extract SDP config
            retap_packets()
            first_run = false

            -- after first pass, try to extract config from SDP if not found in RTP stream
            -- Note: Field values are accessible after retap completes in some Wireshark versions
            -- but the primary extraction happens in the tap.packet callback during first pass

            if not cached_config_bytes then
                twappend("Note: No MP4V-ES config found in RTP stream or SDP.")
                twappend("  Will export raw VOP data only (file may not play).")
            end

            -- second pass: save mp4ves data to target file
            retap_packets()
            close_all_files()
            -- close progress window
            pgtw:close()
            stream_infos = nil
        end

        local function export_all()
            export_mp4ves(false)
        end

        local function export_completed_frames()
            export_mp4ves(true)
        end

        tw:add_button("Export All", export_all)
        tw:add_button("Export Completed Frames (Drop uncompleted frames)", export_completed_frames)
    end

    -- Find this feature in menu "Tools->"Export MP4V-ES to file [Fenngtun's plugins]""
    register_menu("Export MP4V-ES to file [Fenngtun's plugins]", export_mp4ves_to_file, MENU_TOOLS_UNSORTED)
end
