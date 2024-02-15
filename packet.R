library(tidyverse)


# constants
SIGNATURE1 = as.raw(c(0xD4, 0xC3, 0xB2, 0xA1))  # timestamps are in usec
SIGNATURE2 = as.raw(c(0x4D, 0x3C, 0xB2, 0xA1))  # timestamps are in nsec

L2_TYPE <- list()
L2_TYPE[[0x0001]] <- "Ethernet"
L2_TYPE[[0x0071]] <- "Linux SLL"

L3_TYPE <- list()
L3_TYPE[[0x0800]] <- "IPv4"
L3_TYPE[[0x0806]] <- "ARP"

L4_TYPE <- list()


# utils
as_byte <- function(array, byte_offset){
    return(array[byte_offset + 1])
}

# if n = -1, returns rest of the array from byte_offset
as_byte_array <- function(array, byte_offset, n = -1){
    if(n == -1){
        n <- length(array) - byte_offset
    }
    return(array[byte_offset + (1:n)])
}

# NOTE:
# e.g. byte_offset = 0 byte, bit_offset = 0 bit means *MSB* of 1st byte, not LSB
#  (x, y) means (byte_offset, bit_offset)
#  MSB <- | 1st byte    | | 2nd byte    | | 3rd byte    | -> LSB
#         0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1
#         ^ (0, 0)      ^ (0, 7)              ^ (2, 2)
#
# bit_offset must be 0-7 and must not be > 8
as_bit <- function(array, byte_offset, bit_offset){
    byte <- array[byte_offset + 1] %>% as.numeric()
    mask <- 2 ^ (7 - bit_offset)
    return(as.numeric(bitwAnd(byte, mask) != 0))
}

# NOTE:
# e.g. byte_offset = 1 byte, bit_offset = 2 bits, n = 14 bits means
#  MSB <- | 1st byte    | | 2nd byte    | | 3rd byte    | -> LSB
#         0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0 1
#                             <----------HERE----------->
as_bit_array <- function(array, byte_offset, bit_offset, n){
    args <-
        tibble(i = byte_offset * 8 + bit_offset + (1:n) - 1) %>%
        mutate(byte_offset = floor(i / 8), bit_offset = i %% 8) %>%
        select(-i)
    return(pmap_dbl(args, as_bit, array = array))
}

# convert bit array into numeric
weight <- function(bit_array){
    n <- length(bit_array)
    weight <- 2 ^ ((n:1) - 1)
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
read_pcap <- function(path, type = "unknown"){
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

    # DEBUG
    # dfrm <- bind_rows(rows)
    
    dfrm <-
        bind_rows(rows) %>%
        mutate(parsed = map(data, parse_packet, type = type))

    return(list(header = header, dfrm = dfrm))
}


parse_packet <- function(array, type, recursive = T, level = 1){
    if(type == "Ethernet"){
        dfrm <- parse_ethernet(array, level)
    }
    else if(type == "Linux SLL"){
        dfrm <- parse_linux_sll(array, level)
    }
    else if(type == "IPv4"){
        dfrm <- parse_ipv4(array, level)
    }
    else{
        if(type != "none" && !str_starts(type, "unknown")){
            print(str_c("ERROR: parser for ", type, " was not found"))
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


parse_ethernet <- function(array, level = 1){
    l3_type <- as_u16_big(array, 12)
    tryCatch({
        type_next <<- L3_TYPE[[l3_type]]
    },
    error = function(e){
        print(str_c("ERROR: unknown L3 type No. (0x", as.hexmode(l3_type), ")"))
        type_next <<- str_c("unknown (0x", as.hexmode(l3_type), ")")
    })

    return(tibble(
        level = level,
        type = "Ethernet",
        info = list(tibble(
            dst_mac = as_byte_array(array, 0, 6) %>% as_mac(),
            src_mac = as_byte_array(array, 6, 6) %>% as_mac()
            # type = as_u16_big(array, 12)
        )),
        type_next = type_next,
        payload = as_byte_array(array, 14, -1) %>% list(),
        raw_header = as_byte_array(array, 0, 14) %>% list()
    ))
}


parse_linux_sll <- function(array, level = 1){
    l3_type <- as_u16_big(array, 14)
    tryCatch({
        type_next <<- L3_TYPE[[l3_type]]
    },
    error = function(e){
        print(str_c("ERROR: unknown L3 type No. (0x", as.hexmode(l3_type), ")"))
        type_next <<- str_c("unknown (0x", as.hexmode(l3_type), ")")
    })

    return(tibble(
        level = level,
        type = "Linux SLL",
        info = list(tibble(
            packet_type = as_u16_big(array, 0),
            # arphrd = as_u16_big(array, 2),
            # address_length = as_u16_big(array, 4),
            address = as_byte_array(array, 6, address_length) %>% as_mac()
            # type = as_u16_big(array, 14)
        )),
        type_next = type_next,
        payload = as_byte_array(array, 16, -1) %>% list(),
        raw_header = as_byte_array(array, 0, 16) %<% list()
    ))
}

parse_ipv4 <- function(array, level = 1){
    l4_type <- as_u8(array, 9)
    tryCatch({
        type_next <<- L4_TYPE[[l4_type]]
    },
    error = function(e){
        # DEBUG: print(str_c("ERROR: unknown L4 type No. (0x", as.hexmode(l4_type), ")"))
        type_next <<- str_c("unknown (0x", as.hexmode(l4_type), ")")
    })

    return(tibble(
        level = level,
        type = "IPv4",
        info = list(tibble(
            version         = as_bit_array(array, 0, 0, 4) %>% weight(),
            header_length   = as_bit_array(array, 0, 4, 4) %>% weight(),
            ToS             = as_u8(array, 1),
            packet_length   = as_u16_big(array, 2),
            id              = as_u16_big(array, 4),
            dont_fragment   = as_bit(array, 6, 1),
            more_fragment   = as_bit(array, 6, 2),
            fragment_offset = as_bit_array(array, 6, 3, 13) %>% weight(),
            TTL             = as_u8(array, 8),
            src_ip          = as_byte_array(array, 12, 4) %>% as_ipv4(),
            dst_ip          = as_byte_array(array, 16, 4) %>% as_ipv4()
        )),
        type_next = type_next,
        payload = as_byte_array(array, 20, -1) %>% list(),
        raw_header = as_byte_array(array, 0, 20) %>% list()
    ))
}
