#' Tools to Work with 'Snort' Rules, Logs and Data
#'
#' 'Snort' is an open source intrusion prevention system capable of
#' real-time traffic analysis and packet logging. Tools are provided to
#' work with 'Snort' rulesets, logs and other data associated with the platform.
#' More information on 'Snort' can be found at <https://www.snort.org/>.
#'
#' @name porc
#' @docType package
#' @author Bob Rudis (bob@@rud.is)
#' @import stringi
#' @import httr
#' @importFrom ore groups matches ore.search
#' @importFrom rvest html_attr html_node html_nodes html_text
#' @importFrom purrr flatten_df map map_df
#' @importFrom dplyr bind_rows data_frame case_when as_data_frame
#' @importFrom stats complete.cases setNames
#' @importFrom utils packageVersion download.file
NULL
