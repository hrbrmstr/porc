is_blank <- function(x) x == ""

not_blank <- function(x) x != ""

has_colon <- function(x) grepl(":", x, fixed=TRUE)

no_colon <- function(x) !grepl(":", x, fixed=TRUE)

not_na <- function(x) !is.na(x)


#' Helper to class a Snort rules data frame properly
#'
#' @param rules a Snort rules data frame read in with [read_rules()].
#' @export
as_rule_df <- function(rules) {
  class(rules) <- c("tbl_df", "tbl", "snort_rule_df", "data.frame")
  rules
}
