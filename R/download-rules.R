.porc_ua <- function() {
  sprintf("R / porc / %s", utils::packageVersion("porc"))
}

porc_ua <- memoise::memoise(.porc_ua)

#' Download Snort community rules
#'
#' @md
#' @param outpath output path+file. If `NULL` then a date-stamped file will be
#'        created in the current working directory
#' @export
download_community_rules <- function(outpath=NULL) {

  if (is.null(outpath)) outpath <- sprintf("%s-community-rules.tar.gz", Sys.Date())

  download.file(
    "https://www.snort.org/downloads/community/community-rules.tar.gz",
    outpath
  )

}

#' Download Snort subscription rules
#'
#' @md
#' @param version if `NULL` then the latest version will be used, otherwise provide
#'        the version number (with or without dots)
#' @param outpath output path+file. If `NULL` then a date-stamped file will be
#'        created in the current working directory
#' @param overwrite if `TRUE` and the `outpath` file exists then it will be overwritten.
#'        Defaults to `TRUE`
#' @param oinkcode your Snort oinkcode (ideally stored in `OINKCODE` env var)
#' @export
download_subscription_rules <- function(version=NULL, outpath=NULL, overwrite=FALSE,
                                        oinkcode=Sys.getenv("OINKCODE")) {


  if (is.null(version)) {
    res <- httr::GET("https://www.snort.org/downloads", httr::user_agent(porc_ua()))
    pg <- httr::content(res, as="parsed")
    version <- rvest::html_nodes(pg, xpath=".//div[@id='snort_stable_version']/div/div/a[contains(@href, 'snort/snort')]")
    version <- rvest::html_text(version)
    version <- gsub("(snort\\-|\\.tar\\.gz)", "", version[1])
    if (sum(grepl(".", strsplit(version, "")[[1]], fixed=TRUE)) < 3) {
      version <- sprintf("%s.0", version)
    }
    message(sprintf("Downloading subscription rules for version: %s", version))
  }

  version <- gsub("[^[[:digit:]]", "", version)


  if (is.null(outpath)) {
    outpath <- sprintf("%s-snortrules-snapshot-%s.tar.gz", Sys.Date(), version)
  }

  rules_url <- sprintf("https://www.snort.org/rules/snortrules-snapshot-%s.tar.gz",version)

  httr::GET(
    url = rules_url,
    httr::user_agent(porc_ua()),
    httr::write_disk(path = outpath, overwrite = overwrite),
    query = list(
      oinkcode=oinkcode
    ),
    if (interactive()) progress()
  ) -> res

  httr::warn_for_status(res)

}