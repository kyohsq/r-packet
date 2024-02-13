library(tidyverse)


# constants
SIGNATURE1 = as.raw(c(0xD4, 0xC3, 0xB2, 0xA1))  # timestamps are in usec
SIGNATURE2 = as.raw(c(0x4D, 0x3C, 0xB2, 0xA1))  # timestamps are in nsec

L2_TYPE <- list()
L2_TYPE[[113]] <- "Linux SLL"

L3_TYPE <- list()
L3_TYPE[[0x0800]] <- "IPv4"
L3_TYPE[[0x0806]] <- "ARP"

L4_TYPE <- list()


# utils
as_byte <- function(array, byte_offset){
    return(array[byte_offset + 1])
}

# as_bool(array, byte_offset = 0, bit_offset = 0) returns LSB of 1st byte
as_bit <- function(array, byte_offset, bit_offset){
    byte <- array[byte_offset + 1] %>% as.numeric()
    mask <- 2 ^ bit_offset
    return(as.numeric(bitwAnd(byte, mask) != 0))
}

# if n = -1, returns rest of the array from byte_offset
as_byte_array <- function(array, byte_offset, n = -1){
    if(n == -1){
        n <- length(array) - byte_offset
    }
    return(array[byte_offset + (1:n)])
}

as_bit_array <- function(array, byte_offset, bit_offset, n){
    return(map_dbl(bit_offset - 1 + (1:n), as_bit, array = array, byte_offset = byte_offset))
}

as_sub_u8 <- function(array, byte_offset, bit_offset, n){
    bit_array <- as_bit_array(array, byte_offset, bit_offset, n)
    weight <- 2 ^ ((1:n - 1))
    return(sum(bit_array * weight))
}

as_u8 <- function(array, offset){
    sub <- as.numeric(array[offset + 1])
    return(sub)
}

as_u16_little <- function(array, offset){
    sub <- as.numeric(array[offset + (1:2)])
    return(sum(sub * 256 ^ (0:1)))
}

as_u32_little <- function(array, offset){
    sub <- as.numeric(array[offset + (1:4)])
    return(sum(sub * 256 ^ (0:3)))
}

as_u16_big <- function(array, offset){
    sub <- as.numeric(array[offset + (1:2)])
    return(sum(sub * 256 ^ (1:0)))
}

as_u32_big <- function(array, offset){
    sub <- as.numeric(array[offset + (1:4)])
    return(sum(sub * 256 ^ (3:0)))
}

as_mac <- function(array){
    return(array %>% as.character() %>% str_c(collapse = ":"))
}

as_ipv4 <- function(array){
    return(array %>% as.numeric() %>% str_c(collapse = "."))
}


# body
read_pcap <- function(path){
    con <- file(description = path, open = "rb")

    # ==== parse header ====
    array <- readBin(con, what = "raw", n = 24)

    signature <- as_byte_array(array, 0, 4)
    if(all(signature == SIGNATURE1)){
        time_scale = 1e-6  # usec
    }
    else if(all(signature == SIGNATURE2)){
        time_scale = 1e-9  # nsec
    }
    else{
        print("ERROR: file is not pcap")
        return(-1)
    }
    major_version = as_u16_little(array, 4)
    minor_version = as_u16_little(array, 6)
    snap_len = as_u32_little(array, 16)
    link_type = as_u16_little(array, 22)

    header = list(
        time_scale = time_scale,
        major_version = major_version,
        minor_version = minor_version,
        snap_len = snap_len,
        link_type = link_type
    )

    # tentative
    if(link_type == 0){
        link_type <- 113  # to Linux SLL
    }

    tryCatch({
        type <<- L2_TYPE[[link_type]]
    },
    error = function(e){
        type <<- "unknown"
    })

    no <- 1
    rows <- list()
    repeat{
        array <- readBin(con, what = "raw", n = 16)
        if(length(array) < 16){
            break
        }
        time_sub1 <- as_u32_little(array, 0)
        time_sub2 <- as_u32_little(array, 4)
        time <- time_sub1 + time_sub2 * time_scale
        cap_len <- as_u32_little(array, 8)
        org_len <- as_u32_little(array, 12)
        data <- readBin(con, what = "raw", n = cap_len)
        rows[[no]] <- tibble(
            path = path,
            no = no,
            time = time,
            # cap_len = cap_len,
            # org_len = org_len,
            data = list(data)
        )
        no <- no + 1
    }
    close(con)

    dfrm <-
        bind_rows(rows) %>%
        mutate(parsed = map(data, parse_packet, type = type))

    return(list(header = header, dfrm = dfrm))
}


parse_packet <- function(array, type, recursive = T, level = 1){
    if(type == "Linux SLL"){
        dfrm <- parse_linux_sll(array, level)
    }
    else if(type == "IPv4"){
        dfrm <- parse_ipv4(array, level)
    }
    else{
        if(type != "none" && type != "unknown"){
            print(str_c("error: parser for ", type, " was not found"))
        }
        dfrm <- tibble()
        recursive = F  # turn off recursion
    }

    if(recursive && length(dfrm$payload[[1]]) != 0){
        residual <- parse_packet(
            array = dfrm$payload[[1]],
            type = dfrm$type_next[1],
            recursive = T,
            level = level + 1
        )
        dfrm <- bind_rows(dfrm, residual)
    }

    return(dfrm)
}


parse_linux_sll <- function(array, level = 1){
    packet_type <- as_u16_big(array, 0)
    # arphrd <- as_u16_big(array, 2)
    address_length <- as_u16_big(array, 4)
    address <- as_byte_array(array, 6, address_length) %>% as_mac()
    network_type <- as_u16_big(array, 14)
    payload <- as_byte_array(array, 16, -1)

    tryCatch({
        type_next <<- L3_TYPE[[network_type]]
    },
    error = function(e){
        type_next <<- "unknown"
    })

    return(tibble(
        level = level,
        type = "Linux SLL",
        info = list(tibble(
            packet_type = packet_type,
            address = address
        )),
        type_next = type_next,
        payload = list(payload),
        raw = list(array)
    ))
}

parse_ipv4 <- function(array, level = 1){
    ToS <- array[2]
    packet_length <- as_u16_big(array, 2)
    id <- as_u16_big(array, 4)
    dont_fragment <- as_bit(array, 6, 6)
    more_fragment <- as_bit(array, 6, 5)
    fragment_offset <- as_sub_u8(array, 6, 0, 5)
    TTL <- as_u8(array, 8)
    protocol <- as_u8(array, 9)
    src_ip <- as_byte_array(array, 12, 4) %>% as_ipv4()
    dst_ip <- as_byte_array(array, 16, 4) %>% as_ipv4()
    payload <- as_byte_array(array, 20, -1)

    tryCatch({
        type_next <<- L4_TYPE[[protocol]]
    },
    error = function(e){
        type_next <<- "unknown"
    })

    return(tibble(
        level = level,
        type = "IPv4",
        info = list(tibble(
            ToS = ToS,
            packet_length =packet_length,
            id = id,
            dont_fragment = dont_fragment,
            more_fragment = more_fragment,
            fragment_offset = fragment_offset,
            TTL = TTL,
            src_ip = src_ip,
            dst_ip = dst_ip
        )),
        type_next = type_next,
        payload = list(payload),
        raw = list(array)
    ))
}
