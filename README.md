
![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg)
[![Travis-CI Build
Status](https://travis-ci.org/hrbrmstr/porc.svg?branch=master)](https://travis-ci.org/hrbrmstr/porc)
[![Coverage
Status](https://img.shields.io/codecov/c/github/hrbrmstr/porc/master.svg)](https://codecov.io/github/hrbrmstr/porc?branch=master)
[![AppVeyor Build
Status](https://ci.appveyor.com/api/projects/status/github/hrbrmstr/porc?branch=master&svg=true)](https://ci.appveyor.com/project/hrbrmstr/porc)

# porc

Tools to Work with ‘Snort’ Rules, Logs and Data

## Description

‘Snort’ is an open source intrusion prevention system capable of
real-time traffic analysis and packet logging. Tools are provided to
work with ‘Snort’ rulesets, logs and other data associated with the
platform. More information on ‘Snort’ can be found at
<https://www.snort.org/>.

## What’s Inside The Tin

The following functions are implemented:

  - `read_rules`: Parse in a file of snort rules into a data frame
  - `read_extended`: Read a Snort “extended v2” log into a data frame
  - `rule_vars`: Extract all the ‘$’-named variables from Snort rules
  - `as_rule_df`: Helper to class a Snort rules data frame properly

## Installation

``` r
devtools::install_github("hrbrmstr/porc")
```

## Usage

``` r
library(porc)
library(tidyverse)

# current verison
packageVersion("porc")
```

    ## [1] '0.1.0'

## Basic rule reading

``` r
rules <- read_rules(system.file("extdata", "emerging-telnet.rules", package="porc"))

glimpse(rules)
```

    ## Observations: 13
    ## Variables: 10
    ## $ action    <chr> "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert"...
    ## $ protocol  <chr> "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp"
    ## $ src_addr  <chr> "$HOME_NET", "$HOME_NET", "$HOME_NET", "$TELNET_SERVERS", "$TELNET_SERVERS", "$TELNET_SERVERS", "...
    ## $ src_ports <chr> "23", "23", "23", "23", "23", "23", "23", "any", "any", "any", "any", "any", "any"
    ## $ direction <chr> "unidirectional", "unidirectional", "unidirectional", "unidirectional", "unidirectional", "unidir...
    ## $ dst_addr  <chr> "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_N...
    ## $ dst_ports <chr> "any", "any", "any", "any", "any", "any", "any", "[23,2323,3323,4323]", "[23,2323,3323,4323]", "[...
    ## $ commented <lgl> FALSE, TRUE, FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, TRUE, TRUE, FALSE, FALSE, FALSE
    ## $ options   <list> [<# A tibble: 9 x 2,      option,       <chr>, 1       msg, 2      flow, 3   content, 4     dept...
    ## $ id        <int> 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13

``` r
rule_vars(rules)
```

    ## [1] "$EXTERNAL_NET"   "$HOME_NET"       "$TELNET_SERVERS"

``` r
glimpse(rules$options[[1]])
```

    ## Observations: 9
    ## Variables: 2
    ## $ option <chr> "msg", "flow", "content", "depth", "reference", "classtype", "sid", "rev", "metadata"
    ## $ value  <chr> "\"ET TELNET External Telnet Attempt To Cisco Device With No Telnet Password Set (Automatically Diss...

``` r
rules$options[[1]]
```

    ## # A tibble: 9 x 2
    ##      option
    ##       <chr>
    ## 1       msg
    ## 2      flow
    ## 3   content
    ## 4     depth
    ## 5 reference
    ## 6 classtype
    ## 7       sid
    ## 8       rev
    ## 9  metadata
    ## # ... with 1 more variables: value <chr>

## A slightly bigger example

Let’s slurp in all the [Emerging
Threats](https://rules.emergingthreats.net/) Snort feed rules.

Grabbed & unpacked from:
<https://rules.emergingthreats.net/open/snort-edge/emerging.rules.tar.gz>.

``` r
list.files("rules/emerging-rules", "\\.rules$", full.names=TRUE) %>% 
  map_df(~{
    cat(crayon::green(.x), "\n", sep="")
    x <- read_rules(.x)
    if (!is.null(x)) mutate(x, fil = .x)
  }) %>% as_rule_df()-> xdf
```

    ## rules/emerging-rules/emerging-activex.rules
    ## rules/emerging-rules/emerging-attack_response.rules
    ## rules/emerging-rules/emerging-botcc.portgrouped.rules
    ## rules/emerging-rules/emerging-botcc.rules
    ## rules/emerging-rules/emerging-chat.rules
    ## rules/emerging-rules/emerging-ciarmy.rules
    ## rules/emerging-rules/emerging-compromised.rules
    ## rules/emerging-rules/emerging-current_events.rules
    ## rules/emerging-rules/emerging-deleted.rules
    ## rules/emerging-rules/emerging-dns.rules
    ## rules/emerging-rules/emerging-dos.rules
    ## rules/emerging-rules/emerging-drop.rules
    ## rules/emerging-rules/emerging-dshield.rules
    ## rules/emerging-rules/emerging-exploit.rules
    ## rules/emerging-rules/emerging-ftp.rules
    ## rules/emerging-rules/emerging-games.rules
    ## rules/emerging-rules/emerging-icmp_info.rules
    ## rules/emerging-rules/emerging-icmp.rules
    ## rules/emerging-rules/emerging-imap.rules
    ## rules/emerging-rules/emerging-inappropriate.rules
    ## rules/emerging-rules/emerging-info.rules
    ## rules/emerging-rules/emerging-malware.rules
    ## rules/emerging-rules/emerging-misc.rules
    ## rules/emerging-rules/emerging-mobile_malware.rules
    ## rules/emerging-rules/emerging-netbios.rules
    ## rules/emerging-rules/emerging-p2p.rules
    ## rules/emerging-rules/emerging-policy.rules
    ## rules/emerging-rules/emerging-pop3.rules
    ## rules/emerging-rules/emerging-rbn-malvertisers.rules
    ## rules/emerging-rules/emerging-rbn.rules
    ## rules/emerging-rules/emerging-rpc.rules
    ## rules/emerging-rules/emerging-scada.rules
    ## rules/emerging-rules/emerging-scan.rules
    ## rules/emerging-rules/emerging-shellcode.rules
    ## rules/emerging-rules/emerging-smtp.rules
    ## rules/emerging-rules/emerging-snmp.rules
    ## rules/emerging-rules/emerging-sql.rules
    ## rules/emerging-rules/emerging-telnet.rules
    ## rules/emerging-rules/emerging-tftp.rules
    ## rules/emerging-rules/emerging-tor.rules
    ## rules/emerging-rules/emerging-trojan.rules
    ## rules/emerging-rules/emerging-user_agents.rules
    ## rules/emerging-rules/emerging-voip.rules
    ## rules/emerging-rules/emerging-web_client.rules
    ## rules/emerging-rules/emerging-web_server.rules
    ## rules/emerging-rules/emerging-web_specific_apps.rules
    ## rules/emerging-rules/emerging-worm.rules

``` r
glimpse(xdf)
```

    ## Observations: 26,155
    ## Variables: 11
    ## $ action    <chr> "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert", "alert"...
    ## $ protocol  <chr> "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp",...
    ## $ src_addr  <chr> "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_NET", "$EXTERNAL_N...
    ## $ src_ports <chr> "$HTTP_PORTS", "$HTTP_PORTS", "$HTTP_PORTS", "$HTTP_PORTS", "$HTTP_PORTS", "$HTTP_PORTS", "$HTTP_...
    ## $ direction <chr> "unidirectional", "unidirectional", "unidirectional", "unidirectional", "unidirectional", "unidir...
    ## $ dst_addr  <chr> "$HOME_NET", "$HOME_NET", "$HOME_NET", "$HOME_NET", "$HOME_NET", "$HOME_NET", "$HOME_NET", "$HOME...
    ## $ dst_ports <chr> "any", "any", "any", "any", "any", "any", "any", "any", "any", "any", "any", "any", "any", "any",...
    ## $ commented <lgl> FALSE, TRUE, TRUE, FALSE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALSE, FALS...
    ## $ options   <list> [<# A tibble: 20 x 2,       option,        <chr>,  1       msg,  2      flow,  3   content,  4  ...
    ## $ id        <int> 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27...
    ## $ fil       <chr> "rules/emerging-rules/emerging-activex.rules", "rules/emerging-rules/emerging-activex.rules", "ru...

``` r
xdf
```

    ## # A tibble: 26,155 x 11
    ##    action protocol      src_addr   src_ports      direction  dst_addr dst_ports commented           options    id
    ##     <chr>    <chr>         <chr>       <chr>          <chr>     <chr>     <chr>     <lgl>            <list> <int>
    ##  1  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any     FALSE <tibble [20 x 2]>     1
    ##  2  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [23 x 2]>     2
    ##  3  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [16 x 2]>     3
    ##  4  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any     FALSE <tibble [28 x 2]>     4
    ##  5  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [16 x 2]>     5
    ##  6  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [16 x 2]>     6
    ##  7  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [16 x 2]>     7
    ##  8  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [16 x 2]>     8
    ##  9  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [16 x 2]>     9
    ## 10  alert      tcp $EXTERNAL_NET $HTTP_PORTS unidirectional $HOME_NET       any      TRUE <tibble [16 x 2]>    10
    ## # ... with 26,145 more rows, and 1 more variables: fil <chr>

What are the most referenced URLs in Emerging Threats feed?

``` r
unnest(xdf) %>% 
  filter(option == "reference") %>% 
  filter(grepl("^url", value)) %>% 
  select(value) %>% 
  mutate(value = sub("^url,", "", value)) %>% 
  count(value, sort=TRUE)
```

    ## # A tibble: 14,425 x 2
    ##                                                                          value     n
    ##                                                                          <chr> <int>
    ##  1                              doc.emergingthreats.net/bin/view/Main/TorRules  1452
    ##  2                                 doc.emergingthreats.net/bin/view/Main/BotCC   657
    ##  3                                                              sslbl.abuse.ch   608
    ##  4 blog.unmaskparasites.com/2012/06/22/runforestrun-and-pseudo-random-domains/   407
    ##  5        blog.opendns.com/2012/07/10/opendns-security-team-blackhole-exploit/   401
    ##  6                                                  ransomwaretracker.abuse.ch   358
    ##  7                                                        www.shadowserver.org   261
    ##  8                 www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html   211
    ##  9                                                           www.cinsscore.com   200
    ## 10                                                www.networkcloaking.com/cins   200
    ## # ... with 14,415 more rows

## Extended v2 Reading

``` r
evt <- read_extended(system.file("extdata", "multi-record-event-x2.log", package="porc"))

dplyr::glimpse(evt)
```

    ## Observations: 34
    ## Variables: 32
    ## $ sensor_id           <int> 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...
    ## $ event_id            <int> 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89, 89,...
    ## $ event_second        <int> 964798804, 964798804, 964798804, 964798804, 964798804, 964798804, 964798804, 964798804,...
    ## $ event_microsecond   <int> 267362, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 267362, NA, NA,...
    ## $ signature_id        <int> 3, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 3, NA, NA, NA, NA, N...
    ## $ generator_id        <int> 120, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 120, NA, NA, NA, N...
    ## $ signature_revision  <int> 1, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 1, NA, NA, NA, NA, N...
    ## $ classification_id   <int> 2, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 2, NA, NA, NA, NA, N...
    ## $ priority            <int> 3, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 3, NA, NA, NA, NA, N...
    ## $ source_ip_raw       <list> [<cf, 19, 47, 1c>, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, N...
    ## $ destination_ip_raw  <list> [<0a, 14, 0b, 7b>, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, N...
    ## $ sport_itype         <int> 80, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 80, NA, NA, NA, NA,...
    ## $ dport_icode         <int> 2651, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 2651, NA, NA, NA,...
    ## $ protocol            <int> 6, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 6, NA, NA, NA, NA, N...
    ## $ impact_flag         <int> 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, NA, NA, NA, NA, N...
    ## $ impact              <int> 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, NA, NA, NA, NA, N...
    ## $ blocked             <int> 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, NA, NA, NA, NA, N...
    ## $ mpls_label          <int> 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, NA, NA, NA, NA, N...
    ## $ vlan_id             <int> 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, NA, NA, NA, NA, N...
    ## $ pad2                <int> 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, NA, NA, NA, NA, N...
    ## $ rec_type            <chr> "event_v2", "extra_data", "packet", "packet", "packet", "packet", "packet", "packet", "...
    ## $ rec_num             <dbl> 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, ...
    ## $ event_type          <int> NA, 4, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 4, NA, NA, NA, N...
    ## $ event_length        <int> NA, 18602, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 18602, NA, N...
    ## $ type                <int> NA, 13, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 13, NA, NA, NA,...
    ## $ data_type           <int> NA, 1, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 1, NA, NA, NA, N...
    ## $ data_length         <int> NA, 18578, 227, 1163, 820, 1084, 1514, 1514, 1514, 1514, 1514, 1298, 1514, 1514, 1514, ...
    ## $ data                <list> [NULL, <3c, 48, 54, 4d, 4c, 3e, 0a, 3c, 48, 45, 41, 44, 3e, 0a, 09, 3c, 54, 49, 54, 4c...
    ## $ extra_data_type_map <chr> NA, "NORMALIZED_JS", NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, "N...
    ## $ packet_second       <int> NA, NA, 964798804, 964798804, 964798804, 964798804, 964798804, 964798804, 964798804, 96...
    ## $ packet_microsecond  <int> NA, NA, 267362, 276118, 279940, 365865, 374238, 382123, 390039, 482792, 490652, 497184,...
    ## $ link_type           <int> NA, NA, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, NA, NA, 1, 1, 1, 1, 1, 1, 1, 1, 1,...

## Code of Conduct

Please note that this project is released with a [Contributor Code of
Conduct](CONDUCT.md). By participating in this project you agree to
abide by its terms.
