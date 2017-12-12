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
test_that("we can read extended v2 logs", {

  evt <- read_extended(system.file("extdata", "multi-record-event-x2.log", package="porc"))

  expect_equal(dim(evt), c(34L, 32L))

})

context("expand_ranges() functions properly")
test_that("we can expand ranges", {

  rnd <- expand_port_ranges(c("25", "$HTTP_PORTS", "1024:", ":1024", "1:1024", "any"))

  expect_equal(rnd[[1]], "25")
  expect_equal(rnd[[2]], "$HTTP_PORTS")
  expect_equal(rnd[[3]][[10]], "1033")
  expect_equal(rnd[[4]][[100]], "100")
  expect_equal(rnd[[5]][30], "30")
  expect_equal(rnd[[6]], "any")

})

