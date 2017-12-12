#' Parse in a file of snort rules into a data frame
#'
#' The individual components of a Snort rule are parsed and put into a tidy
#' data frame format. The rule options are also parsed and the resultant
#' `options` columns is a data frame with option name and value. The value
#' for options that do not have values is `NA_character`.\cr
#' \cr
#' There is an `id` column which is just an index of the rule position in the
#' file. An extra `commented` field exists to identify rules that are in the
#' file but commented out. This makes it easy to filter on in-use rules.\cr
#' \cr
#' The `options` column can be unnested with `tidyr::unnest()`.
#'
#' @md
#' @param path path to snort rules file
#' @return data frame
#' @export
#' @examples
#' rules <- read_rules(
#'   system.file("extdata", "emerging-telnet.rules", package="porc")
#' )
read_rules <- function(path) {

  path <- normalizePath(path.expand(path))
  if (!file.exists(path)) stop("File not found", call.=FALSE)

  l <- stri_read_lines(path)
  # l <- suppressWarnings(stri_enc_toutf8(l, is_unknown_8bit = TRUE, validate = TRUE))
  l <- stri_trim_both(l)
  l <- Filter(not_blank, l)

  # Everything up to the first left parens is the "header" of the rule
  # The parenthetical section is made up of options that are semicolon-separated

  x <- stri_split_fixed(l, "(", 2, simplify=TRUE)
  x <- as.data.frame(x, stringsAsFactors=FALSE)
  x$V2 <- ifelse(x$V2 == "", NA_character_, x$V2)
  x$V1 <- ifelse(grepl(">", x$V1, fixed=TRUE), x$V1, NA_character_)
  x <- x[complete.cases(x),]
  x <- x[grepl(")", x$V2),]

  if (nrow(x) == 0) return(NULL) # No rules

  x$V2 <- sub(")$", "", x$V2)

  commented <- grepl("^#[[:space:]]*", x$V1)

  x$V1 <- sub("^#[[:space:]]*", "", x$V1)

  as.data.frame(
    stri_split_regex(x$V1, "[[:space:]]+", simplify=TRUE),
    stringsAsFactors=FALSE
  ) -> rule_df

  setNames(rule_df,
    c("action", "protocol", "src_addr", "src_ports", "direction",
      "dst_addr", "dst_ports", "activatedynamic")) -> rule_df

  rule_df <- rule_df[complete.cases(rule_df),]

  rule_df$activatedynamic <- NULL

  rule_df$commented <- commented

  rule_df$direction <- c("->"="unidirectional", "<>"="bidirectional")[rule_df$direction]

  rule_df$options <- lapply(
    stri_split_regex(x$V2, ";[[:space:]]*"),
    function(.x) {
      Filter(not_blank, stri_trim_both(.x))
    }
  )

  rule_df$options <- lapply(rule_df$options, function(.x) {

    noc <- Filter(no_colon, .x)

    .x <- Filter(has_colon, .x)
    .x <- stri_split_fixed(.x, ":", simplify=TRUE)
    .x <- as.data.frame(.x, stringsAsFactors=FALSE)

    class(.x) <- c("tbl_df", "tbl", "data.frame")

    if (length(.x) > 0) {
      .x <- setNames(.x, c("option", "value"))
      .x <- .x[,1:2]
    }

    if (length(noc) > 0) {
      .y <- data.frame(option = noc, value=NA_character_, stringsAsFactors=FALSE)
      if (length(.x) > 0) {
        .x <- rbind(.x, .y)
      } else {
        .x <- .y
      }
    }

    .x

  })

  rule_df$id <- 1:nrow(rule_df)
  rule_df <- as_rule_df(rule_df)

  as_rule_df(rule_df[,1:10])

}

