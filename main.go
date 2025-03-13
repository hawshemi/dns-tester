package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
)

type Provider struct {
	IP   string
	Name string
}

type TestResult struct {
	Name              string
	IP                string
	// Formatted strings for display.
	AvgPing           string
	MinPing           string
	MaxPing           string
	PingMedian        string
	PingJitter        string
	PingLoss          string
	AvgResolveTime    string
	MinResolveTime    string
	MaxResolveTime    string
	ResolveMedian     string
	ResolveJitter     string
	ResolveLoss       string
	// Numeric values used for composite scoring.
	PingAvgVal        float64
	PingMedianVal     float64
	PingJitterVal     float64
	PingLossVal       float64
	ResolveAvgVal     float64
	ResolveMedianVal  float64
	ResolveJitterVal  float64
	ResolveLossVal    float64
}

const (
	failMessage    = "FAIL"
	pingCount      = 6  // increased sample size for ping
	resolveCount   = 6  // increased sample size for DNS resolve
	timeoutSeconds = 2
	maxWorkers     = 10
	maxRetries     = 3
	warmupRounds   = 1
)

// Weights for composite score (you can adjust these).
const (
	weightPingAvg        = 0.25
	weightPingMedian     = 0.25
	weightPingJitter     = 0.25
	weightPingLoss       = 0.25
	weightResolveAvg     = 0.25
	weightResolveMedian  = 0.25
	weightResolveJitter  = 0.25
	weightResolveLoss    = 0.25
)

var (
	providersV4 = []Provider{
		{"1.1.1.1", "Cloudflare (v4)"},
		{"1.1.1.2", "Cloudflare-Security (v4)"},
		{"8.8.8.8", "Google (v4)"},
		{"9.9.9.9", "Quad9 (v4)"},
		{"209.244.0.3", "Level3 (v4)"},
		{"94.140.14.14", "Adguard (v4)"},
		{"193.110.81.0", "Dns0.eu (v4)"},
		{"76.76.2.2", "ControlD (v4)"},
		{"95.85.95.85", "GcoreDNS (v4)"},
		{"185.228.168.9", "CleanBrowsing-Security (v4)"},
		{"208.67.222.222", "OpenDNS (v4)"},
		{"77.88.8.8", "Yandex (v4)"},
		{"77.88.8.88", "Yandex-Safe (v4)"},
		{"64.6.64.6", "UltraDNS (v4)"},
		{"156.154.70.2", "UltraDNS-ThreatProtection (v4)"},
	}

	providersV6 = []Provider{
		{"2606:4700:4700::1111", "Cloudflare (v6)"},
		{"2606:4700:4700::1112", "Cloudflare-Security (v6)"},
		{"2001:4860:4860::8888", "Google (v6)"},
		{"2620:fe::fe", "Quad9 (v6)"},
		{"2a10:50c0::ad1:ff", "Adguard (v6)"},
		{"2a0f:fc80::", "Dns0.eu (v6)"},
		{"2606:1a40::2", "ControlD (v6)"},
		{"2a03:90c0:999d::1", "GcoreDNS (v6)"},
		{"2a0d:2a00:1::2", "CleanBrowsing-Security (v6)"},
		{"2a02:6b8::feed:0ff", "Yandex (v6)"},
		{"2a02:6b8::feed:bad", "Yandex-Safe (v6)"},
		{"2620:74:1b::1:1", "UltraDNS (v6)"},
		{"2610:a1:1018::2", "UltraDNS-ThreatProtection (v6)"},
	}

	domains = []string{
		"www.google.com",
		"www.speedtest.net",
		"i.instagram.com",
	}

	resultPool = &sync.Pool{
		New: func() interface{} {
			return &TestResult{}
		},
	}
)

// statsDetailed computes average, min, max, median and jitter from a slice of float64.
func statsDetailed(times []float64) (avg, min, max, median, jitter float64) {
	if len(times) == 0 {
		return 9999, 9999, 9999, 9999, 9999
	}
	sorted := make([]float64, len(times))
	copy(sorted, times)
	sort.Float64s(sorted)
	min = sorted[0]
	max = sorted[len(sorted)-1]
	sum := 0.0
	for _, t := range times {
		sum += t
	}
	avg = sum / float64(len(times))
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2.0
	} else {
		median = sorted[len(sorted)/2]
	}
	sumSq := 0.0
	for _, t := range times {
		diff := t - avg
		sumSq += diff * diff
	}
	jitter = math.Sqrt(sumSq / float64(len(times)))
	return
}

// parseMs converts strings like "12.3 ms" into a float64.
func parseMs(s string) float64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " ms")
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 9999
	}
	return val
}

// getPingStats runs the ping command, collects individual ping times,
// then computes and returns avg, min, max, median, jitter and packet loss.
func getPingStats(ctx context.Context, ip string) (avg, min, max, median, jitter string, loss float64, times []float64, err error) {
	// Warmup rounds.
	for i := 0; i < warmupRounds; i++ {
		warmupCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		cmd := exec.CommandContext(warmupCtx, "ping", "-c", "1", "-W", strconv.Itoa(timeoutSeconds), ip)
		cmd.Run()
		cancel()
		time.Sleep(100 * time.Millisecond)
	}

	var output []byte
	for retry := 0; retry < maxRetries; retry++ {
		pingCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second*pingCount)
		cmd := exec.CommandContext(pingCtx, "ping", "-c", strconv.Itoa(pingCount), "-W", strconv.Itoa(timeoutSeconds), ip)
		output, err = cmd.CombinedOutput()
		cancel()
		if err == nil {
			break
		}
		time.Sleep(time.Duration(100*(1<<retry)) * time.Millisecond)
	}

	if err != nil {
		return failMessage, failMessage, failMessage, failMessage, failMessage, 9999, nil, err
	}

	// Parse output: collect ping times and packet loss.
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "time=") {
			// Typical line: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=14.2 ms"
			parts := strings.Split(line, "time=")
			if len(parts) >= 2 {
				timeStr := strings.Fields(parts[1])[0]
				if t, err := strconv.ParseFloat(timeStr, 64); err == nil {
					times = append(times, t)
				}
			}
		}
		// Look for packet loss info.
		if strings.Contains(line, "packet loss") {
			// Typical: "4 packets transmitted, 4 received, 0% packet loss, time 3003ms"
			fields := strings.Split(line, ",")
			for _, field := range fields {
				field = strings.TrimSpace(field)
				if strings.Contains(field, "packet loss") || strings.Contains(field, "%") {
					// Extract percentage.
					parts := strings.Fields(field)
					for _, part := range parts {
						if strings.HasSuffix(part, "%") {
							part = strings.TrimSuffix(part, "%")
							if lossVal, err := strconv.ParseFloat(part, 64); err == nil {
								loss = lossVal
							}
						}
					}
				}
			}
		}
	}
	// If we didn't parse loss from output, calculate it.
	if loss == 0 && pingCount > 0 {
		loss = ((float64(pingCount) - float64(len(times))) / float64(pingCount)) * 100.0
	}

	avgVal, minVal, maxVal, medianVal, jitterVal := statsDetailed(times)
	avg = fmt.Sprintf("%.1f ms", avgVal)
	min = fmt.Sprintf("%.1f ms", minVal)
	max = fmt.Sprintf("%.1f ms", maxVal)
	median = fmt.Sprintf("%.1f ms", medianVal)
	jitter = fmt.Sprintf("%.1f ms", jitterVal)
	return
}

// resolveDomain performs DNS resolution using dig and returns all successful query times.
func resolveDomain(ctx context.Context, domain, server string) ([]float64, int, error) {
	var resolveTimes []float64
	successes := 0
	for i := 0; i < resolveCount; i++ {
		var uniqueDomain strings.Builder
		uniqueDomain.WriteString(strconv.FormatInt(time.Now().UnixNano(), 16))
		uniqueDomain.WriteRune('.')
		uniqueDomain.WriteString(domain)

		var output []byte
		var err error
		for retry := 0; retry < maxRetries; retry++ {
			cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			cmd := exec.CommandContext(cmdCtx, "dig", "@"+server, uniqueDomain.String(), "+time="+strconv.Itoa(timeoutSeconds), "+tries=1")
			output, err = cmd.Output()
			cancel()
			if err == nil {
				break
			}
			time.Sleep(time.Duration(100*(1<<retry)) * time.Millisecond)
		}
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Query time") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					if t, err := strconv.Atoi(fields[3]); err == nil {
						resolveTimes = append(resolveTimes, float64(t))
						successes++
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(resolveTimes) == 0 {
		return nil, 0, fmt.Errorf("no successful resolves")
	}
	return resolveTimes, successes, nil
}

func testProvider(ctx context.Context, provider Provider, runs int, resultChan chan<- TestResult, wg *sync.WaitGroup) {
	defer wg.Done()
	result := resultPool.Get().(*TestResult)
	result.Name = provider.Name
	result.IP = provider.IP

	// Run ping tests multiple times and collect results.
	var pingAvgSum, pingMinSum, pingMaxSum, pingMedianSum, pingJitterSum, pingLossSum float64
	var allPingTimes [][]float64
	pingRuns := 0
	for i := 0; i < runs; i++ {
		avgPing, minPing, maxPing, medianPing, pingJitter, pingLoss, pingTimes, err := getPingStats(ctx, provider.IP)
		if err == nil {
			pingAvgSum += parseMs(avgPing)
			pingMinSum += parseMs(minPing)
			pingMaxSum += parseMs(maxPing)
			pingMedianSum += parseMs(medianPing)
			pingJitterSum += parseMs(pingJitter)
			pingLossSum += pingLoss
			allPingTimes = append(allPingTimes, pingTimes)
			pingRuns++
		}
		time.Sleep(100 * time.Millisecond) // Small delay between runs
	}
	if pingRuns > 0 {
		result.AvgPing = fmt.Sprintf("%.1f ms", pingAvgSum/float64(pingRuns))
		result.MinPing = fmt.Sprintf("%.1f ms", pingMinSum/float64(pingRuns))
		result.MaxPing = fmt.Sprintf("%.1f ms", pingMaxSum/float64(pingRuns))
		result.PingMedian = fmt.Sprintf("%.1f ms", pingMedianSum/float64(pingRuns))
		result.PingJitter = fmt.Sprintf("%.1f ms", pingJitterSum/float64(pingRuns))
		result.PingLoss = fmt.Sprintf("%.1f%%", pingLossSum/float64(pingRuns))
		result.PingAvgVal = pingAvgSum / float64(pingRuns)
		var combinedPingTimes []float64
		for _, times := range allPingTimes {
			combinedPingTimes = append(combinedPingTimes, times...)
		}
		_, _, _, result.PingMedianVal, result.PingJitterVal = statsDetailed(combinedPingTimes)
		result.PingLossVal = pingLossSum / float64(pingRuns)
	} else {
		result.AvgPing = failMessage
		result.MinPing = failMessage
		result.MaxPing = failMessage
		result.PingMedian = failMessage
		result.PingJitter = failMessage
		result.PingLoss = "100%"
		result.PingAvgVal = 9999
		result.PingMedianVal = 9999
		result.PingJitterVal = 9999
		result.PingLossVal = 9999
	}

	// Run DNS resolve tests multiple times across all domains.
	var resolveAvgSum, resolveMinSum, resolveMaxSum, resolveMedianSum, resolveJitterSum, resolveLossSum float64
	var allResolveTimes []float64
	var totalDNSAttempts, totalDNSSuccess int
	resolveRuns := 0
	for run := 0; run < runs; run++ {
		var resolveWG sync.WaitGroup
		runResolveTimes := make([][]float64, len(domains))
		runDNSAttempts := len(domains) * resolveCount
		runDNSSuccess := 0

		for i, domain := range domains {
			resolveWG.Add(1)
			go func(idx int, d string) {
				defer resolveWG.Done()
				times, successes, err := resolveDomain(ctx, d, provider.IP)
				if err == nil {
					runResolveTimes[idx] = times
					runDNSSuccess += successes
				}
			}(i, domain)
		}
		resolveWG.Wait()

		var combinedRunResolve []float64
		for _, times := range runResolveTimes {
			combinedRunResolve = append(combinedRunResolve, times...)
		}
		if len(combinedRunResolve) > 0 {
			avgResVal, minResVal, maxResVal, medianResVal, jitterResVal := statsDetailed(combinedRunResolve)
			resolveAvgSum += avgResVal
			resolveMinSum += minResVal
			resolveMaxSum += maxResVal
			resolveMedianSum += medianResVal
			resolveJitterSum += jitterResVal
			resolveLossSum += ((float64(runDNSAttempts) - float64(runDNSSuccess)) / float64(runDNSAttempts)) * 100.0
			allResolveTimes = append(allResolveTimes, combinedRunResolve...)
			totalDNSAttempts += runDNSAttempts
			totalDNSSuccess += runDNSSuccess
			resolveRuns++
		}
		time.Sleep(100 * time.Millisecond) // Small delay between runs
	}
	if resolveRuns > 0 {
		result.AvgResolveTime = fmt.Sprintf("%.1f ms", resolveAvgSum/float64(resolveRuns))
		result.MinResolveTime = fmt.Sprintf("%.1f ms", resolveMinSum/float64(resolveRuns))
		result.MaxResolveTime = fmt.Sprintf("%.1f ms", resolveMaxSum/float64(resolveRuns))
		result.ResolveMedian = fmt.Sprintf("%.1f ms", resolveMedianSum/float64(resolveRuns))
		result.ResolveJitter = fmt.Sprintf("%.1f ms", resolveJitterSum/float64(resolveRuns))
		result.ResolveLoss = fmt.Sprintf("%.1f%%", resolveLossSum/float64(resolveRuns))
		result.ResolveAvgVal = resolveAvgSum / float64(resolveRuns)
		_, _, _, result.ResolveMedianVal, result.ResolveJitterVal = statsDetailed(allResolveTimes)
		result.ResolveLossVal = resolveLossSum / float64(resolveRuns)
	} else {
		result.AvgResolveTime = failMessage
		result.MinResolveTime = failMessage
		result.MaxResolveTime = failMessage
		result.ResolveMedian = failMessage
		result.ResolveJitter = failMessage
		result.ResolveLoss = "100%"
		result.ResolveAvgVal = 9999
		result.ResolveMedianVal = 9999
		result.ResolveJitterVal = 9999
		result.ResolveLossVal = 9999
	}

	resultChan <- *result

	// Reset fields and return to pool.
	result.Name = ""
	result.IP = ""
	result.AvgPing = ""
	result.MinPing = ""
	result.MaxPing = ""
	result.PingMedian = ""
	result.PingJitter = ""
	result.PingLoss = ""
	result.AvgResolveTime = ""
	result.MinResolveTime = ""
	result.MaxResolveTime = ""
	result.ResolveMedian = ""
	result.ResolveJitter = ""
	result.ResolveLoss = ""
	result.PingAvgVal = 0
	result.PingMedianVal = 0
	result.PingJitterVal = 0
	result.PingLossVal = 0
	result.ResolveAvgVal = 0
	result.ResolveMedianVal = 0
	result.ResolveJitterVal = 0
	result.ResolveLossVal = 0
	resultPool.Put(result)
}

// Updated function to save JSON output to file
func saveJSON(results []TestResult) {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}
	err = os.WriteFile("dns-tester-results.json", jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON to file: %v\n", err)
		return
	}
	fmt.Println("Results saved to dns-tester-results.json")
}

// Updated function to save CSV output to file
func saveCSV(results []TestResult) {
	file, err := os.Create("dns-tester-results.csv")
	if err != nil {
		fmt.Printf("Error creating CSV file: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write([]string{
		"Provider", "IP", "Avg Ping", "Median Ping", "Ping Jitter", "Ping Loss",
		"Avg Resolve", "Median Resolve", "Resolve Jitter", "Resolve Loss",
	})
	for _, res := range results {
		writer.Write([]string{
			res.Name,
			res.IP,
			res.AvgPing,
			res.PingMedian,
			res.PingJitter,
			res.PingLoss,
			res.AvgResolveTime,
			res.ResolveMedian,
			res.ResolveJitter,
			res.ResolveLoss,
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Printf("Error writing CSV: %v\n", err)
		return
	}
	fmt.Println("Results saved to dns-tester-results.csv")
}

// Updated printRecommendations to show top 10
func printRecommendations(results []TestResult) {
	// Find best (lowest) values across providers for each metric.
	epsilon := 0.0001
	bestPingAvg := 99999.0
	bestPingMedian := 99999.0
	bestPingJitter := 99999.0
	bestPingLoss := 99999.0
	bestResolveAvg := 99999.0
	bestResolveMedian := 99999.0
	bestResolveJitter := 99999.0
	bestResolveLoss := 99999.0

	for _, r := range results {
		if r.PingAvgVal < bestPingAvg {
			bestPingAvg = r.PingAvgVal
		}
		if r.PingMedianVal < bestPingMedian {
			bestPingMedian = r.PingMedianVal
		}
		if r.PingJitterVal < bestPingJitter {
			bestPingJitter = r.PingJitterVal
		}
		if r.PingLossVal < bestPingLoss {
			bestPingLoss = r.PingLossVal
		}
		if r.ResolveAvgVal < bestResolveAvg {
			bestResolveAvg = r.ResolveAvgVal
		}
		if r.ResolveMedianVal < bestResolveMedian {
			bestResolveMedian = r.ResolveMedianVal
		}
		if r.ResolveJitterVal < bestResolveJitter {
			bestResolveJitter = r.ResolveJitterVal
		}
		if r.ResolveLossVal < bestResolveLoss {
			bestResolveLoss = r.ResolveLossVal
		}
	}

	// Compute composite score for each provider.
	type RankedResult struct {
		TestResult
		CompositeScore float64
	}
	var ranked []RankedResult
	for _, r := range results {
		// Normalize each metric by dividing by the best value (plus epsilon to avoid division by zero).
		pingScore := (r.PingAvgVal/(bestPingAvg+epsilon))*weightPingAvg +
			(r.PingMedianVal/(bestPingMedian+epsilon))*weightPingMedian +
			(r.PingJitterVal/(bestPingJitter+epsilon))*weightPingJitter +
			(r.PingLossVal/(bestPingLoss+epsilon))*weightPingLoss
		resolveScore := (r.ResolveAvgVal/(bestResolveAvg+epsilon))*weightResolveAvg +
			(r.ResolveMedianVal/(bestResolveMedian+epsilon))*weightResolveMedian +
			(r.ResolveJitterVal/(bestResolveJitter+epsilon))*weightResolveJitter +
			(r.ResolveLossVal/(bestResolveLoss+epsilon))*weightResolveLoss
		cs := pingScore + resolveScore
		ranked = append(ranked, RankedResult{r, cs})
	}

	// Sort by composite score (lower is better).
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].CompositeScore < ranked[j].CompositeScore
	})

	// Show top 10 (or fewer if less than 10 results).
	topCount := 10
	if len(ranked) < topCount {
		topCount = len(ranked)
	}
	topResults := ranked[:topCount]

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Rank", "Provider", "IP", "Composite Score", "Avg Ping", "Median Ping", "Ping Jitter", "Ping Loss", "Avg Resolve", "Median Resolve", "Resolve Jitter", "Resolve Loss"})
	for i, rr := range topResults {
		table.Append([]string{
			strconv.Itoa(i + 1),
			rr.Name,
			rr.IP,
			fmt.Sprintf("%.2f", rr.CompositeScore),
			rr.AvgPing,
			rr.PingMedian,
			rr.PingJitter,
			rr.PingLoss,
			rr.AvgResolveTime,
			rr.ResolveMedian,
			rr.ResolveJitter,
			rr.ResolveLoss,
		})
	}
	fmt.Println("\nTop 10 DNS Providers (by composite score):")
	table.Render()
}

// Updated IPv6 detection function
func isIPv6Enabled() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "dig", "-6", "@2606:4700:4700::1111", "google.com", "+time=1", "+tries=1")
	err := cmd.Run()
	return err == nil
}

func main() {
	var outputFormat string
	var testRuns int
	flag.StringVar(&outputFormat, "output", "table", "Output format: table, json, csv")
	flag.StringVar(&outputFormat, "o", "table", "Shorthand for --output")
	flag.IntVar(&testRuns, "runs", 3, "Number of test runs for averaging")
	flag.IntVar(&testRuns, "r", 3, "Shorthand for --runs")
	flag.Parse()

	ctx := context.Background()
	var providers []Provider
	providers = append(providers, providersV4...)
	if isIPv6Enabled() {
		providers = append(providers, providersV6...)
	}
	numProviders := len(providers)
	resultChan := make(chan TestResult, numProviders)
	var results []TestResult

	// Print minimal ASCII banner
	fmt.Println("DNS-Tester")
	fmt.Println("----------")

	// Adjust progress bar for total tasks (providers * runs)
	bar := progressbar.NewOptions(numProviders*testRuns,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription(fmt.Sprintf("Testing DNS providers (%d runs each)", testRuns)),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionSetWriter(os.Stderr), // Redirect progress bar to stderr
	)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxWorkers)
	for _, provider := range providers {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(p Provider) {
			defer func() { <-semaphore }()
			testProvider(ctx, p, testRuns, resultChan, &wg)
			for i := 0; i < testRuns; i++ {
				bar.Add(1) // Increment for each run
			}
		}(provider)
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	for res := range resultChan {
		results = append(results, res)
	}

	// Handle output based on format
	switch outputFormat {
	case "json":
		saveJSON(results)
	case "csv":
		saveCSV(results)
	default:
		// No action for "table" since we only print recommendations
	}
	// Always print top 10 recommendations
	printRecommendations(results)
}
