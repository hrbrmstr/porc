context("read_rules() functions properly")
test_that("we can read rules", {

  rules <- read_rules(system.file("extdata", "emerging-telnet.rules", package="porc"))

  expect_equal(nrow(rules), 13)
  expect_equal(ncol(rules), 10)
  expect_that(rules, is_a("snort_rule_df"))

})

context("rule_vars() functions properly")
test_that("we can read rules", {

  rules <- read_rules(system.file("extdata", "emerging-telnet.rules", package="porc"))

  expect_equal(rule_vars(rules), c("$EXTERNAL_NET", "$HOME_NET", "$TELNET_SERVERS"))

})

context("rule_vars() functions properly")
test_that("we can read rules", {

  evt <- read_extended(system.file("extdata", "multi-record-event-x2.log", package="porc"))

  expect_equal(dim(evt), c(34L, 32L))

})


