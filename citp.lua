citp_proto = Proto("citp","CITP")

-- UDP and TCP Dissector Tables
udp_table = DissectorTable.get("udp.port")
tcp_table = DissectorTable.get("tcp.port")

-- Globals
dissector_version = "1.5"
dissector_date = "2016-07-18"
listeningport = 0
start = 0
count = 0
found_ports = {}
win = nil

ct = {
  -- CITP
  MSEX = "Media Server Extensions",
  PINF = "Peer Information layer",
  PNam = "Peer Name message",
  PLoc = "Peer Location message",
  -- MSEX
  CInf = "Client Information Message",
  SInf = "Server Information Message",
  Nack = "Negative Acknowledge Message",
  LSta = "Layer Status Message",
  StFr = "Stream Frame message",
  RqSt = "Request Stream message",
  GEIn = "Get Element Information message",
  MEIn = "Media Element Information message",
  GETh = "Get Element Thumbnail message",
  EThn = "Element Thumbnail message",
  ELIn = "Element Library Information message",
  GELI = "Get Element Library Information message",
  GELT = "Get Element Library Thumbnail message",
  GVSr = "GetVideoSources",
  VSrc = "Video Sources"
}


-- Fields
citp_fields = {
  -- CITP Fields
  version             = ProtoField.string("citp.version", "Version"),
  request_response_id = ProtoField.uint16("citp.request_response_id", "Request/Response ID"),
  message_size        = ProtoField.uint32("citp.message_size", "Message Size"),
  message_part_count  = ProtoField.uint16("citp.message_part_count", "Message Part Count"),
  message_part        = ProtoField.uint16("citp.message_part", "Message Part"),
  content_type        = ProtoField.string("citp.content_type", "Content Type"),

  -- PInf Fields
  pinf_content_type = ProtoField.string("citp.pinf.content_type", "PInf Content Type"),
  pinf_name = ProtoField.stringz("citp.pinf.name", "Name"),

  -- PInf/PLoc Fields
  pinf_ploc_listening_tcp_port = ProtoField.uint16("citp.pinf.ploc.listening_tcp_port", "Listening TCP Port"),
  pinf_ploc_type               = ProtoField.stringz("citp.pinf.ploc.type", "Type"),
  pinf_ploc_state              = ProtoField.stringz("citp.pinf.ploc.state", "State"),

  -- MSEX Fields
  msex_version         = ProtoField.string("citp.msex.version", "MSEX Version"),
  msex_content_type    = ProtoField.string("citp.msex.content_type", "MSEX Content Type"),
  msex_format          = ProtoField.string("citp.msex.format", "Format"),
  msex_library_type    = ProtoField.uint8("citp.msex.library_type", "Library Type", base.DEC, {
    [1] = "Media",
    [2] = "Effects"
  }),
  msex_library_number    = ProtoField.uint8("citp.msex.library_number", "Library Number"),
  msex_library_id        = ProtoField.string("citp.msex.library_id", "Library ID"),
  msex_parent_library_id = ProtoField.string("citp.msex.parent_library_id", "Parent Library ID"),
  msex_dimensions        = ProtoField.string("citp.msex.dimensions", "Dimensions"),
  msex_fps               = ProtoField.uint8("citp.msex.fps", "FPS"),
  msex_timeout           = ProtoField.uint8("citp.msex.timeout", "Timeout"),
  msex_buffer_size       = ProtoField.uint8("citp.msex.buffer_size", "Buffer Size"),
  msex_buffer            = ProtoField.none("citp.msex.buffer", "Buffer"),

  msex_layer_number = ProtoField.uint8("citp.msex.layer_number", "Layer Number"),

  msex_layer_status                   = ProtoField.uint32("citp.msex.layer.status", "Layer Status", base.HEX),
  msex_layer_status_playing           = ProtoField.uint32("citp.msex.layer.status.playing", "Media Playing", base.DEC, nil, 0x0001),
  msex_layer_status_playback_reverse  = ProtoField.uint32("citp.msex.layer.status.reverse", "Playback Reverse", base.DEC, nil, 0x0002),
  msex_layer_status_playback_looping  = ProtoField.uint32("citp.msex.layer.status.looping", "Playback Looping", base.DEC, nil, 0x0004),
  msex_layer_status_playback_bouncing = ProtoField.uint32("citp.msex.layer.status.bouncing", "Playback Bouncing", base.DEC, nil, 0x0008),
  msex_layer_status_playback_random   = ProtoField.uint32("citp.msex.layer.status.random", "Playback Random", base.DEC, nil, 0x0010),
  msex_layer_status_paused            = ProtoField.uint32("citp.msex.layer.status.paused", "Media Paused", base.DEC, nil, 0x0020),

  msex_physical_output = ProtoField.uint8("citp.msex.physical_output", "Physical Output"),

  msex_source_identifier = ProtoField.uint16("citp.source_identifier", "Source Identifier"),

  msex_thumbnail_flags                 = ProtoField.uint8("citp.msex.thumbnail_flags", "Thumbnail Flags", base.HEX),
  msex_thumbnail_flags_preserve_aspect = ProtoField.uint8("citp.msex.thumbnail_flags.preserve_aspect", "Preserve Aspect Ratio", base.DEC, nil, 0x01),

  msex_library_count   = ProtoField.uint8("citp.msex.library.count", "Library Count"),
  msex_library_count12 = ProtoField.uint16("citp.msex.library.count12", "Library Count"),

  msex_element_count   = ProtoField.uint8("citp.msex.element.count", "Element Count"),
  msex_element_count12 = ProtoField.uint16("citp.msex.element.count12", "Element Count"),

  msex_element_number        = ProtoField.uint8("citp.msex.element.number", "Element Number"),
  msex_element_serial_number = ProtoField.uint32("citp.msex.element.serial_number", "SerialNumber"),
  msex_element_dmx_range_min = ProtoField.uint8("citp.msex.element.dmx_range_min", "DMXRangeMin"),
  msex_element_dmx_range_max = ProtoField.uint8("citp.msex.element.dmx_range_max", "DMXRangeMax"),
  msex_element_name          = ProtoField.string("citp.msex.element.name", "Name"),

  msex_media_position  = ProtoField.uint32("citp.msex.media.position", "Media Position"),
  msex_media_length    = ProtoField.uint32("citp.msex.media.length", "Media Length"),
  msex_media_timestamp = ProtoField.uint64("citp.msex.media.timestamp", "Media Timestamp"),

  msex_server_uuid = ProtoField.string("citp.msex.server.uuid", "UUID"),

  msex_source_flags                 = ProtoField.uint16("citp.msex.source_flags", "Source Flags", base.HEX),
  msex_source_flags_without_effects = ProtoField.uint16("citp.msex.source_flags.without_effects", "Without Effects", base.DEC, nil, 0x0001),

  -- MSEX/CInf Fields
  msex_cinf_supported_version_count = ProtoField.uint8("citp.msex.cinf.supported_version_count", "Supported Version Count"),
  msex_cinf_supported_version       = ProtoField.string("citp.msex.cinf.supported_version", "Supported Version"),

  -- MSEX/SInf Fields
  msex_sinf_product_name            = ProtoField.string("citp.msex.sinf.product_name", "Product Name"),
  msex_sinf_product_version         = ProtoField.string("citp.msex.sinf.product_version", "Product Version"),
  msex_sinf_supported_version_count = ProtoField.uint8("citp.msex.sinf.supported_version_count", "Supported Version Count"),

  msex_sinf_supported_library_types                = ProtoField.uint16("citp.msex.sinf.supported_library_types", "Supported Library Types", base.HEX),
  msex_sinf_supported_library_types_media          = ProtoField.uint16("citp.msex.sinf.supported_library_types_media", "Media (Images & Video)", base.DEC, nil, 0x0001),
  msex_sinf_supported_library_types_effects        = ProtoField.uint16("citp.msex.sinf.supported_library_types_effects", "Effects", base.DEC, nil, 0x0002),
  msex_sinf_supported_library_types_cues           = ProtoField.uint16("citp.msex.sinf.supported_library_types_cues", "Cues", base.DEC, nil, 0x0004),
  msex_sinf_supported_library_types_crossfades     = ProtoField.uint16("citp.msex.sinf.supported_library_types_crossfades", "Crossfades", base.DEC, nil, 0x0008),
  msex_sinf_supported_library_types_masks          = ProtoField.uint16("citp.msex.sinf.supported_library_types_masks", "Masks", base.DEC, nil, 0x0010),
  msex_sinf_supported_library_types_blend_effects  = ProtoField.uint16("citp.msex.sinf.supported_library_types_blend_effects", "Blend presets", base.DEC, nil, 0x0020),
  msex_sinf_supported_library_types_effect_presets = ProtoField.uint16("citp.msex.sinf.supported_library_types_effect_presets", "Effect presets", base.DEC, nil, 0x0040),
  msex_sinf_supported_library_types_image_presets  = ProtoField.uint16("citp.msex.sinf.supported_library_types_image_presets", "Image presets", base.DEC, nil, 0x0080),
  msex_sinf_supported_library_types_3d_meshes      = ProtoField.uint16("citp.msex.sinf.supported_library_types_3d_meshes", "3D meshes", base.DEC, nil, 0x0100),

  msex_sinf_thumbnail_format_count  = ProtoField.uint8("citp.msex.sinf.thumbnail_format_count", "Thumbnail Format Count"),
  msex_sinf_stream_format_count     = ProtoField.uint8("citp.msex.sinf.stream_format_count", "Stream Format Count"),
  msex_sinf_layer_count             = ProtoField.uint8("citp.msex.sinf.layer_count", "Layer Count"),
  msex_sinf_layer_information       = ProtoField.string("citp.msex.sinf.layer_information", "Layer Information"),

  -- MSEX/Nack Fields
  msex_nack_received_content_type = ProtoField.string("citp.msex.nack.received_content_type", "Received MSEX Content Type"),

  -- MSEX/VSrc Fields
  msex_vsrc_source_count = ProtoField.uint16("citp.vsrc.source.count", "Source Count"),
  msex_vsrc_source_name  = ProtoField.string("citp.vsrc.source.name", "Source Name"),
}

citp_proto.fields = citp_fields

function citp_proto.dissector(buffer,pinfo,tree)
  listeningport = 0
  start = 0
  
  -- Check for buffer lengths less the CITP Header (20 Bytes)
  if buffer:len() < 20 then  -- We don't have enough to figure out message length
    pinfo.desegment_len = 20 - buffer:len() -- get more data.
    return
  end
  
  count = 4
  
  cookie = buffer(start,count):string()
  pinfo.cols.protocol = cookie
  subtree = tree:add_le(citp_proto, buffer(), string.format("Controller Interface Transport Protocol,  Length: %d Header: 20", buffer:len()))
  start = start + count
  
  count = 1
  citp_version = string.format("%d.%d", buffer(start,count):le_uint(), buffer(start+1,count):le_uint())
  subtree:add_le(citp_fields.version, buffer(start,2), citp_version)

  start = start + 2

  subtree:add_le(citp_fields.request_response_id, buffer(start,2), buffer(start,2):le_uint())
  
  message_size = buffer(8,4):le_uint()

  subtree:add_le(citp_fields.message_size, buffer(8,4), buffer(8,4):le_uint())
  subtree:add_le(citp_fields.message_part_count, buffer(12,2), buffer(12,2):le_uint())
  subtree:add_le(citp_fields.message_part, buffer(14,2), buffer(14,2):le_uint())
  
  start = 16

  content_type = buffer(start,4):string()

  str = ct[content_type] or "(Unknown)"
  str = string.format("- %s, Length: %d", str, string.len(buffer(20):string()))
  
  subtree, value = subtree:add_packet_field(citp_fields.content_type, buffer(16,4), ENC_STRING, str)
  
  pinfo.cols.info = "CITP " .. citp_version .. " > " .. content_type
  
  -- Calculate message size and reassemble PDUs if needed.
  if message_size > buffer:len() then
    pinfo.desegment_len = message_size - buffer:len()
    return
  end

  start = 20

  -- PINF - Peer Information layer -----------------------------------------------
  if content_type == "PINF" then

    pinf_content_type = buffer(start,4):string()

    str = ct[pinf_content_type] or "(Unknown)"

    subtree, value = subtree:add_packet_field(citp_fields.pinf_content_type, buffer(start,4), ENC_STRING, "- " .. str)

    start = start + 4

    pinfo.cols.info:append(" > " .. pinf_content_type)

    -- PINF/PNam -----------------------------------------------------------------
    if pinf_content_type == "PNam" then
      name, count = citp_extract_ucs1(buffer, start)
      subtree:add_le(citp_fields.pinf_name, buffer(start, count))
    end -- PName
    
    -- PINF/PLoc -----------------------------------------------------------------
    if pinf_content_type == "PLoc" then
      listeningport = buffer(start,2):le_uint()

      subtree:add_le(citp_fields.pinf_ploc_listening_tcp_port, buffer(start,2))
      
      -- If listening port is non zero then add to the dissector
      if listeningport then
        CITP_add_port(listeningport)
      end
      listeningport = 0
      
      start = start + 2

      str, count = citp_extract_ucs1(buffer, start)
      subtree:add_le(citp_fields.pinf_ploc_type, buffer(start, count))
      start = start + count
      
      name, count = citp_extract_ucs1(buffer, start)
      subtree:add_le(citp_fields.pinf_name, buffer(start, count))
      start = start+count
      
      str, count = citp_extract_ucs1(buffer, start)
      subtree:add_le(citp_fields.pinf_ploc_state, buffer(start, count))
    end -- PLoc

    pinfo.cols.info:append(" > " .. name)
  end -- PINF
  
  -- MSEX ------------------------------------------------------------------------
  if content_type == "MSEX" then
    local str = ""
    
    version = buffer(start,1):uint() .. "." .. buffer(start+1,1):uint()
    subtree:add_le(citp_fields.msex_version, buffer(start+1,2), version)

    start = start + 2

    msex_content_type = buffer(start,4):string()

    str = ct[msex_content_type] or "(Unknown)"
    
    subtree, value = subtree:add_packet_field(citp_fields.msex_content_type, buffer(22,4), ENC_STRING, "- " .. str)
    
    start = start + 4

    pinfo.cols.info:append (" " .. version .. " > " .. msex_content_type)

    -- MSEX/CInf - Client Information message ------------------------------------
    if msex_content_type == "CInf" then
      subtree, value = subtree:add_packet_field(citp_fields.msex_cinf_supported_version_count, buffer(start,1), ENC_LITTLE_ENDIAN)

      start = start+1

      for i=1,buffer(start-1,1):uint() do
        local support_version = buffer(start+1,1):uint() .. "." .. buffer(start,1):uint()
        subtree:add_le(citp_fields.msex_cinf_supported_version, buffer(start,2), support_version)
        start = start+2
      end
    end -- CInf
    
    -- MSEX/SInf - Server Information message ------------------------------------
    if msex_content_type == "SInf" then
      if version >= "1.2" then
        count = 36
        subtree:add_le(citp_fields.msex_server_uuid, buffer(start,count), buffer(start,count))
        start = start + count
      end

      -- Product Name (ASCII)
      str, count = citp_extract_ucs2(buffer, start)
      pinfo.cols.info:append(" > Server: " .. str)
      subtree:add_le(citp_fields.msex_sinf_product_name, buffer(start, count), str)
      start = start + count
      
      count = 2
      local product_version = buffer(start,1):le_uint() .. "." .. buffer(start+1,1):le_uint()

      if version >= "1.2" then
        count = 3
        product_version = product_version .. "." .. buffer(start+2,1)
      end

      pinfo.cols.info:append(" (" .. product_version .. ")")
      subtree:add_le(citp_fields.msex_sinf_product_version, buffer(start,count), product_version)
      start = start + count
      
      if version >= "1.2" then
        version_subtree, value = subtree:add_packet_field(citp_fields.msex_sinf_supported_version_count, buffer(start,1), ENC_LITTLE_ENDIAN)

        start = start + 1 
        for i=1,buffer(start-1,1):uint() do
          local support_version = buffer(start,1):uint() .. "." .. buffer(start+1,1):uint()
          subtree:add_le(citp_fields.msex_version, buffer(start,2), support_version)
          start = start+2
        end

        subtree:add_le(citp_fields.msex_sinf_supported_library_types, buffer(start,1))

        start = start + 1

        thumbnail_subtree, value = subtree:add_packet_field(citp_fields.msex_sinf_thumbnail_format_count, buffer(start,1), ENC_LITTLE_ENDIAN)

        start = start + 1 
        for i=0,buffer(start-1,1):uint() do
          thumbnail_subtree:add_le(citp_fields.msex_format, buffer(start,4))
          start = start+4
        end

        stream_subtree, value = subtree:add_packet_field(citp_fields.msex_sinf_stream_format_count, buffer(start,1), ENC_LITTLE_ENDIAN)

        start = start + 1 
        for i=0,buffer(start-1,1):uint() do
          stream_subtree:add_le(citp_fields.msex_format, buffer(start,4))
          start = start+4
        end

      end -- Version 1.2

      count = 1
      layercount = buffer(start, count):uint()
      layer_subtree, value = subtree:add_packet_field(citp_fields.msex_sinf_layer_count, buffer(start,count), ENC_LITTLE_ENDIAN)
      start = start + count
      
      for i = 1, layercount do
        info, count = citp_extract_ucs1(buffer, start)
        layer_subtree:add_le(citp_fields.msex_sinf_layer_information, buffer(start, count), "Layer ".. i .." DMX (proto/net/uni/chan.): " .. info)
        start = start + count
      end
      pinfo.cols.info:append(", Layers: " .. layercount)
    end -- SInf
    
    -- MSEX/Nack - Negative Acknowledge message ----------------------------------
    if msex_content_type == "Nack" then
      subtree:add_le(citp_fields.msex_nack_received_content_type, buffer(start))
    end -- Nack
    
    -- MSEX/StFr - Stream Frame message ------------------------------------------
    if msex_content_type == "StFr" then
      if version >= "1.2" then
        subtree:add_le(citp_fields.msex_server_uuid, buffer(start,36))
        start = start + 36
      end

      -- Source ID
      count = 2
      sourceIdentifier = buffer(start,count):le_uint()
      subtree:add_le(citp_fields.msex_source_identifier, buffer(start,count))
      start = start + count
      
      -- Thumbs Format
      count = 4
      frameFormat = buffer(start,count):string()
      subtree:add_le(citp_fields.msex_format, buffer(start,count))
      start = start + count
      
      -- Dimentions
      dims, count = extract_msex_dimensions (buffer, start)
      subtree:add_le(citp_fields.msex_dimensions, buffer(start,count), dims)
      start = start + count
      
      -- Buffer Size
      count = 2
      subtree:add_le(citp_fields.msex_buffer_size, buffer(start,count))
      start = start + count
      
      subtree:add_le(citp_fields.msex_buffer, buffer(start))

      pinfo.cols.info:append (string.format(" > Source:%d %s %s",
                                            sourceIdentifier,
                                            frameFormat,
                                            dims
                                            ))
    end -- StFr
    
    -- MSEX/RqSt - Request Stream message ----------------------------------------
    if msex_content_type == "RqSt" then
      -- Source ID
      count = 2
      local sourceIdentifier = buffer(start,count):le_uint()
      subtree:add_le(citp_fields.msex_source_identifier, buffer(start,count))
      start = start + count
      
      -- Frame Format
      count = 4
      local frameFormat = buffer(start,count):string()
      subtree:add_le(citp_fields.msex_format, buffer(start,count))
      start = start + count
      
      -- Dimentions
      dims, count = extract_msex_dimensions (buffer, start)
      subtree:add_le(citp_fields.msex_dimensions, buffer(start,count))
      start = start + count
      
      -- FPS
      count = 1
      local fps = buffer(start,count):le_uint()
      subtree:add_le(citp_fields.msex_fps, buffer(start,count))
      start = start + count
      
      -- Timeout
      count = 1
      local timeout = buffer(start,count):le_uint()
      subtree:add_le(citp_fields.msex_timeout, buffer(start,count))
      start = start + count
      
      --info
      pinfo.cols.info:append (string.format(" > Source:%d %s %s@%d %dSec",
                                            sourceIdentifier,
                                            frameFormat,
                                            dims,
                                            fps,
                                            timeout))
    end -- RqSt
    
    -- MSEX/EThn - Element Thumbnail message -------------------------------------
    if msex_content_type == "EThn" then
      
      subtree:add_le(citp_fields.msex_library_type, buffer(start,1))

      start = start + 1
      
      if version == "1.0" then
        count = 1
        libraryNumber = buffer(start,count):le_uint()
        subtree:add_le(citp_fields.msex_library_number, buffer(start,count))
      elseif version <= "1.2" then
        libraryNumber, count = extract_msex_library_id(buffer, start)
        subtree:add_le(citp_fields.msex_library_id, buffer(start,count), libraryNumber)
      end

      start = start + count
      
      -- Element
      count = 1
      element = buffer(start,count):uint()
      subtree:add_le(citp_fields.msex_element_number, buffer(start,count))
      start = start + count
      
      -- Thumbnail Format
      count = 4
      subtree:add_le(citp_fields.msex_format, buffer(start,count))
      start = start + count
      
      -- Dimentions
      dims, count = extract_msex_dimensions (buffer, start)
      subtree:add_le(citp_fields.msex_dimensions, buffer(start,count), dims)
      start = start + count
      
      --Thumb Buffer
      count = 2
      buffer_subtree, value = subtree:add_packet_field(citp_fields.msex_buffer_size, buffer(start,count), ENC_LITTLE_ENDIAN)
      start = start + count
      
      -- Remainder of packet is frame data, or part of frame data
      buffer_subtree:add_le(citp_fields.msex_buffer, buffer(start))
      
      --info
      pinfo.cols.info:append(string.format(" > LibraryID:%s Element:%d",
                                           libraryNumber,
                                           element))

    end -- EThn
    
    -- MSEX/ELIn - Element Library Information message ---------------------------
    if msex_content_type == "ELIn" then
      
      -- Library Type
      count = 1
      subtree:add_le(citp_fields.msex_library_type, buffer(start,count))
      start = start + count
      
      if version <= "1.2" then
        count = 1
        element_count = buffer(start,count):uint()
        element_tree, value = subtree:add_packet_field(citp_fields.msex_library_count, buffer(start,count), ENC_LITTLE_ENDIAN)
      else
        count = 2
        element_count = buffer(start,count):uint()
        element_tree, value = subtree:add_packet_field(citp_fields.msex_library_count12, buffer(start,count), ENC_LITTLE_ENDIAN)
      end

      start = start + count
      
      for i = 1, element_count do
        if version == "1.0" then
          count = 1
          lib_tree, value = element_tree:add_packet_field(citp_fields.msex_library_number, buffer(start,count), ENC_LITTLE_ENDIAN)
          lib_treee:add_le(citp_fields.msex_library_number, buffer(start,count), ENC_LITTLE_ENDIAN)
        else
          str, count = extract_msex_library_id(buffer, start)
          lib_tree, value = element_tree:add_packet_field(citp_fields.msex_library_id, buffer(start,count), ENC_STRING)
          lib_tree:set_text("Library ID: " .. str)
          lib_tree:add_le(citp_fields.msex_library_id, buffer(start,count), str)
        end
        start = start + count
        
        if version >= "1.2" then
          count = 4
          lib_tree:add_le(citp_fields.msex_element_serial_number, buffer(start,count))
          start = start + count
        end

        -- DMX Min
        count = 1
        lib_tree:add_le(citp_fields.msex_element_dmx_range_min, buffer(start,count))
        start = start + count
        
        -- DMX Max
        count = 1
        lib_tree:add_le(citp_fields.msex_element_dmx_range_max, buffer(start,count))
        start = start + count
        
        str, count = citp_extract_ucs2(buffer, start)
        lib_tree:add_le(citp_fields.msex_element_name, buffer(start, count), str)
        start = start + count
        
        if version == "1.1" then
          count = 1
          lib_tree:add_le(citp_fields.msex_library_count, buffer(start,count))
          start = start + count
        end
        
        if version >= "1.2" then
          count = 2
          lib_tree:add_le(citp_fields.msex_library_count12, buffer(start,count))
          start = start + count
        end
      
        if version <= "1.1" then 
          count = 1
          lib_tree:add_le(citp_fields.msex_element_count, buffer(start,count))
        else
          count = 2
          lib_tree:add_le(citp_fields.msex_element_count12, buffer(start,count))
        end

        start = start + count
      end
      pinfo.cols.info:append(" > Elements: " .. element_count)
      
    end -- ELIn
    
    -- MSEX/LSta - Layer Status message ------------------------------------------
    if msex_content_type == "LSta" then
      
      count = 1
      layercount = buffer(start,count):uint() 
      layers_subtree, value = subtree:add_packet_field(citp_fields.msex_library_count, buffer(start,count), ENC_LITTLE_ENDIAN)
      start = start + count

      for i = 1, layercount do
        
        count = 1
        -- TODO: use dummy field to higlight whole layer " (".. buffer(start+2,1):uint().."/"..buffer(start+3,1):uint()..")"
        layer_subtree, value = layers_subtree:add_packet_field(citp_fields.msex_layer_number, buffer(start,count), ENC_LITTLE_ENDIAN)

        layer_subtree:add_le(citp_fields.msex_layer_number, buffer(start,count))
        start = start + count
        
        count = 1
        layer_subtree:add_le(citp_fields.msex_physical_output, buffer(start,count))
        start = start + count
        
        if version >= "1.2" then
          count = 1
          layer_subtree:add_le(citp_fields.msex_library_type, buffer(start, count))
          start = start + count
        end

        if version <= "1.1" then
          count = 1
          layer_subtree:add_le(citp_fields.msex_library_number, buffer(start,count))
          start = start + count
        else
          LibraryID, count = extract_msex_library_id (buffer, start)
          subtree:add_le(citp_fields.msex_library_id, buffer(start,count), LibraryID)
          start = start + count
        end

        count = 1
        layer_subtree:add_le(citp_fields.msex_element_number, buffer(start,count))
        start = start + count
        
        str, count = citp_extract_ucs2(buffer, start)
        layer_subtree:add_le(citp_fields.msex_element_name, buffer(start,count), str)
        start = start + count
        
        count = 4
        layer_subtree:add_le(citp_fields.msex_media_position, buffer(start,count))
        start = start + count
        
        count = 4
        layer_subtree:add_le(citp_fields.msex_media_length, buffer(start,count))
        start = start + count
        
        count = 1
        layer_subtree:add_le(citp_fields.msex_fps, buffer(start,count))
        start = start + count

        count = 4
        flag_subtree, value = layer_subtree:add_packet_field(citp_fields.msex_layer_status, buffer(start,count), ENC_LITTLE_ENDIAN)
        flag_subtree:add_le(citp_fields.msex_layer_status_playing, buffer(start,count))
        flag_subtree:add_le(citp_fields.msex_layer_status_playback_reverse, buffer(start,count))
        flag_subtree:add_le(citp_fields.msex_layer_status_playback_looping, buffer(start,count))
        flag_subtree:add_le(citp_fields.msex_layer_status_playback_bouncing, buffer(start,count))
        flag_subtree:add_le(citp_fields.msex_layer_status_playback_random, buffer(start,count))
        flag_subtree:add_le(citp_fields.msex_layer_status_paused, buffer(start,count))
        start = start + count
      end -- end for : Layer Count

      pinfo.cols.info:append (string.format(" Layer Count:%d",layercount))
    end -- LSta
    
    -- MSEX/MEIn - Media Element Information message -----------------------------
    if msex_content_type == "MEIn" then
      
      if verison == "1.0" then
        count = 1
        library_number = buffer(start,count):uint()
        subtree:add_le(citp_fields.msex_library_number, buffer(start,count))

        pinfo.cols.info:append(" > Library Number: " .. library_number)

        start = start + count
      else
        library_id, count = extract_msex_library_id(buffer, start)
        subtree:add_le(citp_fields.msex_library_id, buffer(start,count), library_id)

        pinfo.cols.info:append(" > Library ID: " .. library_id)

        start = start + count
      end

      if version <= "1.1" then
        count = 1

        element_count = buffer(start,count):uint()
        elements_subtree, value = subtree:add_packet_field(citp_fields.msex_element_count, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      else
        count = 2

        element_count = buffer(start,count):uint()
        elements_subtree, value = subtree:add_packet_field(citp_fields.msex_element_count12, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      end
      
      for i = 1, element_count do
        count = 1
        -- TODO: Add dummy field
        element_subtree = elements_subtree:add_packet_field(citp_fields.msex_element_number, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
        
        if version >= "1.2" then
          count = 4
          element_subtree:add_le(citp_fields.msex_element_serial_number, buffer(start,count))
          start = start + count
        end

        count = 1
        element_subtree:add_le(citp_fields.msex_element_dmx_range_min, buffer(start,count))
        start = start + count
        
        count = 1
        element_subtree:add_le(citp_fields.msex_element_dmx_range_max, buffer(start,count))
        start = start + count
        
        str, count = citp_extract_ucs2(buffer, start)
        element_subtree:add_le(citp_fields.msex_element_name, buffer(start,count), str)
        start = start + count

        -- TODO: convert

        count = 8
        element_subtree:add_le(citp_fields.msex_media_timestamp, buffer(start,count))
        start = start + count

        --[[ This is a hack because le_uint64() returns the bigendian result
        count = 8
        epoch = 0
        mult = 1
        
        for j=0, count - 1 do
          epoch = epoch + (buffer(start+j, 1):uint() * mult)
          mult = mult * 256
        end
        
        -- The time OSX displays and the epoch caluclation is off by a number of minues.
        -- epoch and os.date seem to jive, but OSX time is wrong?
        element_subtree:add_le(buffer(start,count),string.format("Time: %s (epoch:%d)", os.date("%c", epoch), epoch))
        ]]--

        -- Dimentions
        dims, count = extract_msex_dimensions (buffer, start)
        element_subtree:add_le(citp_fields.msex_dimensions, buffer(start,count), dims)
        start = start + count
        
        count = 4
        element_subtree:add_le(citp_fields.msex_media_length, buffer(start,count))
        start = start + count
        
        count = 1
        element_subtree:add_le(citp_fields.msex_fps, buffer(start,count))
        start = start + count
        
      end
      
      pinfo.cols.info:append(string.format(", Elements: %d", element_count))
    end -- MEIn
    
    -- MSEX/GEIn - Get Element Information message -------------------------------
    if msex_content_type == "GEIn" then
      
      count = 1
      subtree:add_le(citp_fields.msex_library_type, buffer(start,count))
      start = start + count

      if verison == "1.0" then
        count = 1
        library_number = buffer(start,count):uint()
        subtree:add_le(citp_fields.msex_library_number, buffer(start,count))

        pinfo.cols.info:append(" > Library Number: " .. library_number)

        start = start + count
      else
        library_id, count = extract_msex_library_id(buffer, start)
        subtree:add_le(citp_fields.msex_library_id, buffer(start,count), library_id)

        pinfo.cols.info:append(" > Library ID: " .. library_id)

        start = start + count
      end

      if version <= "1.1" then
        count = 1

        element_count = buffer(start,count):uint()
        elements_subtree, value = subtree:add_packet_field(citp_fields.msex_element_count, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      else
        count = 2

        element_count = buffer(start,count):uint()
        elements_subtree, value = subtree:add_packet_field(citp_fields.msex_element_count12, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      end
      
      for i = 1, element_count do
        count = 1
        elements_subtree:add_le(citp_fields.msex_element_number, buffer(start,count))
        start = start + count
      end
      
      pinfo.cols.info:append(string.format(", Elements: %d", element_count))
    end -- GEIn
   
    -- MSEX/GELI - Get Element Library Information message -----------------------
    if msex_content_type == "GELI" then
      
      count = 1
      subtree:add_le(citp_fields.msex_library_type, buffer(start,count))
      start = start + count

      
      if version >= "1.1" then
        parent_library_id, count = extract_msex_library_id(buffer, start)
        subtree:add_le(citp_fields.msex_parent_library_id, buffer(start,count))
        start = start + count
      end

      if version <= "1.1" then
        count = 1

        library_count = buffer(start,count):uint()
        library_subtree, value = subtree:add_packet_field(citp_fields.msex_library_count, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      else
        count = 2

        library_count = buffer(start,count):uint()
        library_subtree, value = subtree:add_packet_field(citp_fields.msex_library_count12, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      end
      
      count = 1
      for i = 1, library_count do
        library_subtree:add_le(citp_fields.msex_library_number, buffer(start,count))
        start = start + count
      end

      pinfo.cols.info:append(" > Library Count: " .. library_count)
    end -- GELI
    
    -- MSEX/GELT - Get Element Library Thumbnail message -------------------------
    if msex_content_type == "GELT" then

      count = 4
      subtree:add_le(citp_fields.msex_format, buffer(start,count))
      start = start + count
      
      dims, count = extract_msex_dimensions (buffer, start)
      subtree:add_le(citp_fields.msex_dimensions, buffer(start,count), dims)
      start = start + count
      
      count = 1
      flag_subtree, value = subtree:add_packet_field(citp_fields.msex_thumbnail_flags, buffer(start,count), ENC_LITTLE_ENDIAN)
      flag_subtree:add_le(citp_fields.msex_thumbnail_flags_preserve_aspect, buffer(start,count))
      start = start + count
      
      count = 1
      subtree:add_le(citp_fields.msex_library_type, buffer(start,count))
      start = start + count
      
      if version <= "1.1" then
        count = 1
        library_count = buffer(start,count):uint()
        library_subtree, value = subtree:add_packet_field(citp_fields.msex_library_count, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      else
        count = 2
        library_count = buffer(start,count):uint()
        library_subtree, value = subtree:add_packet_field(citp_fields.msex_library_count12, buffer(start,count), ENC_LITTLE_ENDIAN)
        start = start + count
      end
      
      for i = 1, library_count do
        if version == "1.0" then
          count = 1
          subtree:add_le(citp_fields.msex_library_number, buffer(start,count))
        else
          library_id, count = extract_msex_library_id(buffer, start)
          subtree:add_le(citp_fields.msex_library_id, buffer(start,count), library_id)
        end
        start = start + count
      end

      pinfo.cols.info:append(" > Library Count: " .. library_count)
      
    end -- GELT
    
    -- MSEX/GETh - Get Element Get Element Thumbnail message ---------------------
    if msex_content_type == "GETh" then
      
      -- Thumbnail Format
      count = 4
      subtree:add_le(citp_fields.msex_format, buffer(start,count))
      start = start + count
      
      -- Width x Height
      dims, count = extract_msex_dimensions (buffer, start)
      subtree:add_le(citp_fields.msex_dimensions, buffer(start,count), dims)
      start = start + count
      
      -- Thumbnail Flags
      count = 1
      flag_subtree, value = subtree:add_packet_field(citp_fields.msex_thumbnail_flags, buffer(start,count), ENC_LITTLE_ENDIAN)
      flag_subtree:add_le(citp_fields.msex_thumbnail_flags_preserve_aspect, buffer(start,count))
      start = start +1
      
      -- Library Type
      subtree:add_le(citp_fields.msex_library_type, buffer(start, 1))
      start = start + 1
      
      if version == "1.0" then
        count = 1
        subtree:add_le(citp_fields.msex_library_number, buffer(start,count))
        start = start + count
      else
        library_id, count = extract_msex_library_id (buffer, start)
        subtree:add_le(citp_fields.msex_library_id, buffer(start,count), library_id)
        start = start + count
      end

      if version <= "1.1" then
        count = 1
        element_count = buffer(start,count):le_uint()
        element_subtree, value = subtree:add_packet_field(citp_fields.msex_element_count, buffer(start,count), ENC_LITTLE_ENDIAN)
      else
        count = 2
        element_count = buffer(start,count):le_uint()
        element_subtree, value = subtree:add_packet_field(citp_fields.msex_element_count12, buffer(start,count), ENC_LITTLE_ENDIAN)
      end

      start = start + count
      
      -- Element Numbers
      for i = 1, element_count do
        element_subtree:add_le(citp_fields.msex_element_number, buffer(start,count))
        start = start + count
      end

      pinfo.cols.info:append(" > Elements " .. element_count)

    end -- GETh
    
    -- MSEX/GVSr - GetVideoSources -----------------------------------------------
    if msex_content_type == "GVSr" then
    end -- GVSr

    -- MSEX/VSrc - Video Sources -------------------------------------------------
    if msex_content_type == "VSrc" then
      
      -- Source Count
      count = 2
      source_count = buffer(start,count):le_uint()
      sources_subtree, value = subtree:add_packet_field(citp_fields.msex_vsrc_source_count, buffer(start,count), ENC_LITTLE_ENDIAN)
      start = start + count
      
      for i = 1, source_count do
        -- Source Identifier
        count = 2
        source_subtree, value = sources_subtree:add_le(citp_fields.msex_source_identifier, buffer(start,count))
        source_subtree:add_le(citp_fields.msex_source_identifier, buffer(start,count))
        start = start + count
        
        -- Source Name
        str, count = citp_extract_ucs2(buffer, start)
        source_subtree:add_le(citp_fields.msex_vsrc_source_name, buffer(start,count), str)
        start = start + count
        
        -- Physical Output
        count = 1
        source_subtree:add_le(citp_fields.msex_physical_output, buffer(start,count))
        start = start + count

        -- Layer Number
        count = 1
        source_subtree:add_le(citp_fields.msex_layer_number, buffer(start,count))
        start = start + count

        -- Flags
        count = 2
        flag_subtree, value = source_subtree:add_packet_field(citp_fields.msex_source_flags, buffer(start,count), ENC_LITTLE_ENDIAN)
        flag_subtree:add_le(citp_fields.msex_source_flags_without_effects, buffer(start,count))
        start = start + count
        
        -- Width x Height
        dim, count = extract_msex_dimensions (buffer, start)
        source_subtree:add_le(citp_fields.msex_dimensions, buffer(start,count), dim)
        start = start + count
      end
    end -- VSrc
    
  end -- MSEX
  
end -- end citp_proto.dissector

-- -------------------------------------------------------------------------------
-- Formatters
-- -------------------------------------------------------------------------------

function citp_extract_ucs1(buffer, start)
  local str = buffer(start):stringz()
  local count = string.len(str) + 1
  return str, count
end

function citp_extract_ucs2(buffer, start)
  local str = buffer(start):le_ustringz()
  local count = (string.len(str) + 1) * 2
  return str, count
end

function extract_msex_library_id(buffer, start)
  local str = string.format("%d,%d,%d,%d", 
    buffer(start,1):uint(),
    buffer(start+1,1):uint(),
    buffer(start+2,1):uint(),
    buffer(start+3,1):uint()
  )
  return str, 4
end

function extract_msex_dimensions(buffer, start)
  local count = 2
  local width = buffer(start,count):le_uint()
  local height = buffer(start+2,count):le_uint()
  
  count = 4
  local str = string.format("%dx%d", width, height)
  return str, count
end

-- Add TCP Port
-- port is based in PINF listen port
function CITP_add_port(port)
  if port > 0 then
    if not found_ports[port] then
      found_ports[port] = true
      tcp_table:add(port, citp_proto)
      win_log = string.format("Added CITP Port: %d\n", port)
      if win == nil then
        win = TextWindow.new("CITP dissector " .. dissector_version .. " (" .. dissector_date .. ")")
      end

      win:append(win_log)
      win_log = ""
    end
  end
end

-- always using UDP 4809
udp_table:add(4809,citp_proto)

--Debug, Add Mbox
--CITP_add_port(6436) -- PRG Mbox
--CITP_add_port(4011) -- Arkaos Media Master
