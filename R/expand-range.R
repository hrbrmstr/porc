sprintf("(%s)", paste0(c(
  "^(?<var>\\$[[:alpha:][:digit:]_]+)$",
  "(?<any>any)",
  "^(?<single>[[:digit:]]+)$",
  "(?<l>[[:digit:]]+)\\:(?<r>[[:digit:]]+)",
  "^\\:(?<to>[[:digit:]]+)",
  "(?<from>[[:digit:]]+)\\:$"
), collapse = "|")) -> snort_ranges_regex_text


#' Expand a Snort port description
#'
#' Snort rule port descriptions can be anything from a single number, to `any`,
#' to a `$` variable specifier to a full or partial range. This function will
#' identify full or partial ranges and expand then, leaving other port descriptors
#' untouched.
#'
#' @md
#' @return list
#' @param x character vector of individual port strings
#' @export
#' @examples
#' expand_port_ranges(c("25", "$HTTP_PORTS", "1024:", ":1024", "1:1024", "any"))
expand_port_ranges <- function(x) {

  snort_ranges_regex <- ore::ore(snort_ranges_regex_text)

  y <- ore::groups(ore::ore.search(snort_ranges_regex, x, simplify=FALSE))
  z <- dplyr::as_data_frame(t(y[,,]))

  purrr::map(1:nrow(z), ~{
    zq <- z[.x,]
    if (!(is.na(zq$single))) { return(zq$single) }
    if (!(is.na(zq$var))) { return(zq$var) }
    if (!(is.na(zq$any))) { return("any") }
    if (complete.cases(zq[,c("l", "r")])) { return(as.character(seq(as.numeric(zq$l), as.numeric(zq$r), 1))) }
    if (!(is.na(zq$to))) { return(as.character(seq(1, as.numeric(zq$to), 1))) }
    if (!(is.na(zq$from))) { return(as.character(seq(as.numeric(zq$from), 65535, 1))) }
    return(NA_character_)
  })

}
