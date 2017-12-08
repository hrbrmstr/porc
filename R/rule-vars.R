#' Extract all the `$`-named variables from Snort rules
#'
#' @param rules a Snort rules data frame read in with [read_rules()].
#' @export
#' @examples
#' rules <- read_rules(
#'   system.file("extdata", "emerging-telnet.rules", package="porc")
#' )
#'
#' rule_vars(rules)
rule_vars <- function(rules) {

  if (!inherits(rules, "snort_rule_df")) stop("Not a Snort rules data frame", call.=FALSE)

  unlist(
    list(rules$src_addr, rules$src_ports, rules$dst_addr, rules$dst_ports),
    use.names=FALSE
  ) -> x

  x <- stri_extract_all_regex(x, "(\\$[[:alpha:]_]+)")
  x <- unlist(x, use.names=FALSE)
  x <- as.vector(x)
  unique(sort(x))

}
