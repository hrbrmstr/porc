app_id_length <-  16

valid_record_types <- list(
  packet = 2,
  event = 7,
  event_ipv6 = 72,
  event_v2 = 104,
  event_ipv6_v2 = 105,
  extra_data = 110,
  event_appid = 111,
  event_appid_ipv6 = 112,
  appstat = 113
)

record_type_map <- list(
  `2` = "packet",
  `7` = "event",
  `72` = "event_ipv6",
  `104` = "event_v2",
  `105` = "event_ipv6_v2",
  `110` = "extra_data",
  `111` = "event_appid",
  `112` = "event_appid_ipv6",
  `113` = "appstat"
)

extra_data_type <- list(
  `1` = "XFF_IP4",
  `2` = "XFF_IP6",
  `3` = "REVIEWED_BY",
  `4` = "GZIP_DATA",
  `5` = "SMTP_FILENAME",
  `6` = "SMTP_MAIL_FROM",
  `7` = "SMTP_RCPT_TO",
  `8` = "SMTP_HEADERS",
  `9` = "HTTP_URI",
  `10` = "HTTP_HOSTNAME",
  `11` = "IP6_SRC_ADDR",
  `12` = "IP6_DST_ADDR",
  `13` = "NORMALIZED_JS"
)

packet_fields  <- list(
  "sensor_id" = list(what="integer", n=1, size=4),
  "event_id" = list(what="integer", n=1, size=4),
  "event_second" = list(what="integer", n=1, size=4),
  "packet_second" = list(what="integer", n=1, size=4),
  "packet_microsecond" = list(what="integer", n=1, size=4),
  "link_type" = list(what="integer", n=1, size=4),
  "data_length" = list(what="integer", n=1, size=4)
)

event_fields <-  list(
  "sensor_id" = list(what="integer", n=1, size=4),
  "event_id" = list(what="integer", n=1, size=4),
  "event_second" = list(what="integer", n=1, size=4),
  "event_microsecond" = list(what="integer", n=1, size=4),
  "signature_id" = list(what="integer", n=1, size=4),
  "generator_id" = list(what="integer", n=1, size=4),
  "signature_revision" = list(what="integer", n=1, size=4),
  "classification_id" = list(what="integer", n=1, size=4),
  "priority" = list(what="integer", n=1, size=4),
  "source_ip_raw" = list(what = "raw", n=4, size=1),
  "destination_ip_raw" = list(what = "raw", n=4, size=1),
  "sport_itype" = list(what = "integer", n=1, size=2),
  "dport_icode" = list(what = "integer", n=1, size=2),
  "protocol" = list(what = "integer", n=1, size=1),
  "impact_flag" = list(what = "integer", n=1, size=1),
  "impact" = list(what = "integer", n=1, size=1),
  "blocked" = list(what = "integer", n=1, size=1)
)

event_v2_fields <- append(
  event_fields,
  list(
    "mpls_label" = list(what = "integer", n=1, size=4),
    "vlan_id" = list(what = "integer", n=1, size=2),
    "pad2" = list(what = "integer", n=1, size=2)
  )
)

event_ipv6_fields <- list(
  "sensor_id" = list(what = "integer", n=1, size=4),
  "event_id" = list(what = "integer", n=1, size=4),
  "event_second" = list(what = "integer", n=1, size=4),
  "event_microsecond" = list(what = "integer", n=1, size=4),
  "signature_id" = list(what = "integer", n=1, size=4),
  "generator_id" = list(what = "integer", n=1, size=4),
  "signature_revision" = list(what = "integer", n=1, size=4),
  "classification_id" = list(what = "integer", n=1, size=4),
  "priority" = list(what = "integer", n=1, size=4),
  "source_ip_raw" = list(what = "raw", n=16, size=1),
  "destination_ip_raw" = list(what = "raw", n=16, size=1),
  "sport_itype" = list(what = "integer", n=1, size=2),
  "dport_icode" = list(what = "integer", n=1, size=2),
  "protocol" = list(what = "integer", n=1, size=1),
  "impact_flag" = list(what = "integer", n=1, size=1),
  "impact" = list(what = "integer", n=1, size=1),
  "blocked" = list(what = "integer", n=1, size=1)
)

event_v2_ipv6_fields <- append(
  event_ipv6_fields,
  list(
    "mpls_label" = list(what = "integer", n=1, size=4),
    "vlan_id" = list(what = "integer", n=1, size=2),
    "pad2" = list(what = "integer", n=1, size=2)
  )
)

extra_data_fields <- list(
  "event_type" = list(what = "integer", n = 1, size = 4),
  "event_length" = list(what = "integer", n = 1, size = 4),
  "sensor_id" = list(what = "integer", n = 1, size = 4),
  "event_id" = list(what = "integer", n = 1, size = 4),
  "event_second" = list(what = "integer", n = 1, size = 4),
  "type" = list(what = "integer", n = 1, size = 4),
  "data_type" = list(what = "integer", n = 1, size = 4),
  "data_length" = list(what = "integer", n = 1, size = 4)
)

list(
  `2` = packet_fields,
  `7` = event_fields,
  `72` = event_ipv6_fields,
  `104` = event_v2_fields,
  `106` = event_v2_ipv6_fields,
  `110` = extra_data_fields#,
  # `111` = event_appid_fields,
  # `112` = event_appid_ipv6_fields,
  # `113` = appstat_fields
) -> field_map

read_fields <- function(con, type, length) {

  buf <- readBin(con, what = "raw", n = length, size =1)

  rec_con <- rawConnection(buf)

  rec <- field_map[[as.character(type)]]

  purrr::map(rec, ~{
    readBin(rec_con, what = .x$what, n = .x$n, size = .x$size, endian="big")
  }) -> r

  if (type %in% c(valid_record_types$extra_data, valid_record_types$packet)) {
    r$data <- list(readBin(rec_con, what="raw", size=1, n=r$data_length))
  }

  if (type %in% c(valid_record_types$extra_data)) {
    r$extra_data_type_map <- extra_data_type[[r$type]]
  }

  r$rec_type <- record_type_map[[as.character(type)]]

  if ("source_ip_raw" %in% names(r)) r$source_ip_raw <- list(r$source_ip_raw)
  if ("destination_ip_raw" %in% names(r)) r$destination_ip_raw <- list(r$destination_ip_raw)

  # iptools::numeric_to_ip(to_int(f$`source-ip.raw`))
  # iptools::numeric_to_ip(to_int(f$`destination-ip.raw`))

  close(rec_con)

  r

}

read_header <- function(con) {
  buf <- readBin(con, what = integer(), n = 2, endian = "big")
  buf <- if (length(buf) > 0) buf <- as.list(setNames(buf, c("type", "length"))) else NULL
  buf
}

#' Read a Snort "extended v2" log into a data frame
#'
#' @param path path to log file
#' @return data frame
#' @export
#' @examples
#' read_extended(system.file("extdata", "multi-record-event-x2.log", package="porc"))
read_extended <- function(path) {

  path <- normalizePath(path.expand(path))

  sz <- file.size(path)
  guess_rec_count <- round(sz/2000)

  con <- file(path, open = "rb")
  ofs <- seek(con, seek(con))

  log_recs <- vector(mode = "list", length = guess_rec_count)

  idx <- 1

  while(!is.null(hdr <- read_header(con))) {
    f <- read_fields(con, hdr$type, hdr$length)
    f$rec_num <- idx
    log_recs[[idx]] <- f
    idx <- idx + 1
  }

  close(con)

  dplyr::bind_rows(log_recs[1:(idx-1)])

}
