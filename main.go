package main

import (
  "flag"
  "net/http"
  "log"
  "os"
  "bufio"
  "regexp"
  "reflect"
  "strings"
  "github.com/prometheus/client_golang/prometheus"
  "github.com/prometheus/client_golang/prometheus/promhttp"
)


var addr = flag.String("listen-address", ":8080",
  "The address to listen on for HTTP requests.")


type fooCollector struct {
	pamSessionOpened *prometheus.Desc
	pamSessionClosed *prometheus.Desc
	maxAuthAttempts *prometheus.Desc
	invalidUser *prometheus.Desc
	userNotAllowed *prometheus.Desc
}

func authLogCollector() *fooCollector {
	return &fooCollector{
		pamSessionOpened: prometheus.NewDesc("auth_pam_session_opened",
			"Shows count of all loged in users for time",
			[]string{"user"}, nil,
		),
		pamSessionClosed: prometheus.NewDesc("auth_pam_session_closed",
			"Shows count of all loged out users for time",
			[]string{"user"}, nil,
		),
		maxAuthAttempts: prometheus.NewDesc("auth_max_auth_attempts",
			"Shows count of failed attempts to login for user",
			[]string{"user"}, nil,
		),
		invalidUser: prometheus.NewDesc("auth_invalid_user",
			"Shows count of trying to login by unregistered users",
			[]string{"user"}, nil,
		),
		userNotAllowed: prometheus.NewDesc("auth_user_not_allowed",
			"Shows count of trying to login by unauthorized users",
			[]string{"user"}, nil,
		),
	}
}

func (collector *fooCollector) Describe(ch chan<- *prometheus.Desc) {

	ch <- collector.pamSessionOpened
	ch <- collector.pamSessionClosed
	ch <- collector.maxAuthAttempts
	ch <- collector.invalidUser
	ch <- collector.userNotAllowed
}


func parserAuthLog(template string) map[string]string {
    usernames := make(map[string]string)

    f, err := os.Open("auth.log")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)

    var r = regexp.MustCompile("^(?P<date>[A-Z][a-z]{2}\\s+\\d{1,2}) (?P<time>(\\d{2}:?){3}) (?P<hostname>[a-zA-Z_\\-\\.]+) (?P<processName>[a-zA-Z_\\-]+)(\\[(?P<pid>\\d+)\\])?: " + template)

    for scanner.Scan() {
        if r.MatchString(scanner.Text()) {
            match := r.FindStringSubmatch(scanner.Text())
            result := make(map[string]string)
            for i, name := range r.SubexpNames() {
                if i != 0 && name != "" {
                    result[name] = match[i]
                }
            }

            if _, found := usernames[result["username"]]; found {
                    continue
            } else {
                    usernames[result["username"]] = result["username"]
            }
        }
    }
    return(usernames)
}

func getCount(template string) map[string]float64 {
    metrics :=  make(map[string]float64)
    var parserValue float64 = 0
    keys := reflect.ValueOf(parserAuthLog(template)).MapKeys()
    strkeys := make([]string, len(keys))
    for i := 0; i < len(keys); i++ {
	parserValue = 0
        strkeys[i] = keys[i].String()

        f, err := os.Open("auth.log")
        if err != nil {
            log.Fatal(err)
        }
        defer f.Close()

        scanner := bufio.NewScanner(f)
        r, err := regexp.Compile(strings.Split(template, "(?P<username>.*)")[0] + strkeys[i] + strings.Split(template, "(?P<username>.*)")[1] )

        if err != nil {
            log.Fatal(err)
        }

        for scanner.Scan() {
            if r.MatchString(scanner.Text()) {
                parserValue += 1
            }
        }

        if err := scanner.Err(); err != nil {
            log.Fatal(err)
        }

	metrics[strkeys[i]] = parserValue

    }
    return(metrics)
}


func (collector *fooCollector) Collect(ch chan<- prometheus.Metric) {

	pamSessionOpenedValue := getCount("pam_unix\\(.*\\): session opened for user (?P<username>.*) by")
	pamSessionClosedValue := getCount("pam_unix\\(.*\\): session closed for user (?P<username>.*)")
	maxAuthAttemptsValue := getCount("error: maximum authentication attempts exceeded for invalid user (?P<username>.*) from (?P<ipAddress>.*) port \\d+ .*")
	invalidUserValue := getCount("Invalid user (?P<username>.*) from (?P<ipAddress>.*)")
	userNotAllowedValue := getCount("User (?P<username>.*) from (?P<ipAddress>.*) not allowed because not listed in .*")

	psoKeys := reflect.ValueOf(pamSessionOpenedValue).MapKeys()
        psoStrkeys := make([]string, len(psoKeys))
        for i := 0; i < len(psoKeys); i++ {
                psoStrkeys[i] = psoKeys[i].String()
	        ch <- prometheus.MustNewConstMetric(collector.pamSessionOpened, prometheus.CounterValue, pamSessionOpenedValue[psoStrkeys[i]], psoStrkeys[i])
	}

        pscKeys := reflect.ValueOf(pamSessionClosedValue).MapKeys()
        pscStrkeys := make([]string, len(pscKeys))
        for i := 0; i < len(pscKeys); i++ {
                pscStrkeys[i] = pscKeys[i].String()
	        ch <- prometheus.MustNewConstMetric(collector.pamSessionClosed, prometheus.CounterValue, pamSessionClosedValue[pscStrkeys[i]], pscStrkeys[i])
        }

        maaKeys := reflect.ValueOf(maxAuthAttemptsValue).MapKeys()
        maaStrkeys := make([]string, len(maaKeys))
        for i := 0; i < len(maaKeys); i++ {
                maaStrkeys[i] = maaKeys[i].String()
                ch <- prometheus.MustNewConstMetric(collector.maxAuthAttempts, prometheus.CounterValue, maxAuthAttemptsValue[maaStrkeys[i]], maaStrkeys[i])
        }

        iuKeys := reflect.ValueOf(invalidUserValue).MapKeys()
        iuStrkeys := make([]string, len(iuKeys))
        for i := 0; i < len(iuKeys); i++ {
                iuStrkeys[i] = iuKeys[i].String()
	        ch <- prometheus.MustNewConstMetric(collector.invalidUser, prometheus.CounterValue, invalidUserValue[iuStrkeys[i]], iuStrkeys[i])
        }

        unaKeys := reflect.ValueOf(userNotAllowedValue).MapKeys()
        unaStrkeys := make([]string, len(unaKeys))
        for i := 0; i < len(unaKeys); i++ {
                unaStrkeys[i] = unaKeys[i].String()
	        ch <- prometheus.MustNewConstMetric(collector.userNotAllowed, prometheus.CounterValue, userNotAllowedValue[unaStrkeys[i]], unaStrkeys[i])
        }

}

func main() {
  flag.Parse()

  authLog := authLogCollector()
  prometheus.MustRegister(authLog)

  http.Handle("/metrics", promhttp.Handler())
  log.Printf("Starting web server at %s\n", *addr)
  err := http.ListenAndServe(*addr, nil)
  if err != nil {
    log.Printf("http.ListenAndServer: %v\n", err)
  }
}
