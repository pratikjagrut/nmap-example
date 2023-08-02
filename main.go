package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
)

type CipherData struct {
	Ciphers     []string `json:"ciphers"`
	Compressors []string `json:"compressors"`
	Preference  string   `json:"cipher_preference"`
	Warnings    []string `json:"warnings"`
}

type TLSVersions struct {
	TLS10    CipherData `json:"TLSv1.0"`
	TLS11    CipherData `json:"TLSv1.1"`
	TLS12    CipherData `json:"TLSv1.2"`
	TLS13    CipherData `json:"TLSv1.3"`
	Strength string     `json:"least_strength"`
}

type HostInfo struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Ports     []Port   `json:"ports"`
}

type Port struct {
	ID       uint16      `json:"id"`
	Protocol string      `json:"protocol"`
	Service  string      `json:"service"`
	State    string      `json:"state"`
	TLS      TLSVersions `json:"ssl-enum-ciphers"`
}

type Hosts struct {
	Hosts []HostInfo `json:"hosts"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	hosts := []string{"google.com", "meta.com"}
	ports := []string{"443", "80"}

	// Run Nmap and get the output
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(hosts...),
		nmap.WithPorts(ports...),
		nmap.WithScripts("ssl-enum-ciphers"),
	)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if warnings != nil && len(*warnings) > 0 {
		fmt.Println("Warnings:", warnings)
	}

	parsedHosts := parseNmapOutput(result)
	jsonData, err := json.MarshalIndent(parsedHosts, "", "  ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(string(jsonData))
}

func parseNmapOutput(result *nmap.Run) Hosts {
	hosts := Hosts{}
	if len(result.Hosts) == 0 {
		fmt.Println("No hosts found.")
		return hosts
	}
	for _, host := range result.Hosts {
		hostInfo := HostInfo{}
		hostInfo.IP = host.Addresses[0].String()
		for _, hostname := range host.Hostnames {
			hostInfo.Hostnames = append(hostInfo.Hostnames, hostname.Name)
		}

		for _, port := range host.Ports {
			p := Port{
				ID:       port.ID,
				Protocol: port.Protocol,
				Service:  port.Service.Name,
				State:    port.State.State,
			}
			for _, script := range port.Scripts {
				tlsVersions, strength := parseOutput(script.Output)
				p.TLS.TLS10 = tlsVersions["TLSv1.0"]
				p.TLS.TLS11 = tlsVersions["TLSv1.1"]
				p.TLS.TLS12 = tlsVersions["TLSv1.2"]
				p.TLS.TLS13 = tlsVersions["TLSv1.3"]
				p.TLS.Strength = strength
			}
			hostInfo.Ports = append(hostInfo.Ports, p)
		}
		hosts.Hosts = append(hosts.Hosts, hostInfo)
	}

	return hosts
}

func parseOutput(output string) (map[string]CipherData, string) {
	tlsVersions := make(map[string]CipherData)
	var strength string
	lines := strings.Split(output, "\n")
	var key string
	var currentTLSVersion string

	for _, line := range lines {
		if strings.Contains(line, "TLSv") {
			// Start of a new TLS version section
			currentTLSVersion = strings.Replace(strings.TrimSpace(line), ":", "", -1)
			tlsVersions[currentTLSVersion] = CipherData{}
			key = "" // Reset key when starting a new section
		} else if strings.Contains(line, "ciphers") ||
			strings.Contains(line, "compressors") ||
			strings.Contains(line, "cipher preference") ||
			strings.Contains(line, "warnings") {
			// Detect the key for the current section
			key = strings.Replace(strings.TrimSpace(line), ":", "", -1)
		}

		if key != "" && currentTLSVersion != "" && !strings.Contains(line, "least strength") {
			// Append line to the corresponding field in CipherData
			data := tlsVersions[currentTLSVersion]
			if key == "ciphers" {
				c := strings.TrimSpace(line)
				if !strings.Contains(c, "ciphers") {
					data.Ciphers = append(data.Ciphers, c)
				}
			} else if key == "compressors" {
				c := strings.TrimSpace(line)
				if c != "NULL" && !strings.Contains(c, "compressors") {
					data.Compressors = append(data.Compressors, c)
				}
			} else if key == "warnings" {
				c := strings.TrimSpace(line)
				if !strings.Contains(c, "warnings") {
					data.Warnings = append(data.Warnings, c)
				}
			} else if strings.Contains(key, "cipher preference") {
				data.Preference = strings.TrimSpace(strings.Split(key, " ")[2])
			}
			tlsVersions[currentTLSVersion] = data
		} else if strings.Contains(line, "least strength") {
			l := strings.Split(line, " ")
			strength = strings.TrimSpace(l[len(l)-1])
		}
	}

	return tlsVersions, strength
}
