package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config 配置结构
type Config struct {
	Port         string
	VMMS         string
	VMMPort      string
	VMPath       string
	VMPort       string
	Xieyi        string
	UUID         string
	Youxuan      string
	SubName      string
	SubURL       string
	Baohuo       string
	NezhaServer  string
	NezhaKey     string
	NezhaPort    string
	NezhaTLS     string
	FilePath     string
	Tok          string
	HostName     string
	AgentUUID    string
	NezhaHasPort bool
	VPort        string

	// 下载链接
	NezhaURLX64    string
	NezhaURLARM64  string
	NezhaURLBSD    string
	NezhaURLX64Alt string
	NezhaURLARM64Alt string
	NezhaURLBSDAlt string
	WebURLX64      string
	WebURLARM64    string
	WebURLBSD      string
	CFFURLX64      string
	CFFURLARM64    string
	CFFURLBSD      string

	// 文件名
	WebFilename   string
	NezhaFilename string
	CFFFilename   string
}

// Global variables
var (
	config        Config
	countryName   = "未知"
	upURL         = ""
	encodedURL    = ""
	lastHostName  = ""
	lastSentTime  int64
	mu            sync.Mutex
)

// VmessConfig Vmess 配置结构
type VmessConfig struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	Aid  string `json:"aid"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
}

func main() {
	// 初始化配置
	initConfig()

	// 打印信息
	fmt.Println("==============================")
	fmt.Println()
	fmt.Println("     /info 系统信息")
	fmt.Println("     /start 检查进程")
	fmt.Printf("     /%s 订阅\n", config.UUID)
	fmt.Println()
	fmt.Println("==============================")

	// 初始化下载
	initializeDownloads(func() {
		// 15秒后检查进程
		time.AfterFunc(15*time.Second, func() {
			checkProcesses()
		})

		// 20秒后初始化数据
		time.AfterFunc(20*time.Second, func() {
			initializeData()
			if config.SubURL != "" {
				startCronJob()
			}
		})

		// 启动进程检查
		startCheckingProcesses()

		// 如果 nezha 有端口，执行 upname
		if config.NezhaHasPort {
			go upname()
			ticker := time.NewTicker(1 * time.Minute)
			go func() {
				for range ticker.C {
					upname()
				}
			}()
		}
	})

	// 设置路由
	setupRoutes()

	// 启动服务器
	fmt.Printf("nx-app listening on port %s!\n==============================\n", config.Port)
	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		fmt.Printf("Server failed to start: %v\n", err)
	}
}

// initConfig 初始化配置
func initConfig() {
	config.Port = getEnv("SERVER_PORT", getEnv("NX_PORT", "3000"))
	config.VMMS = getEnv("VPATH", "vls-123456")
	config.VMMPort = getEnv("VL_PORT", "8002")
	config.VMPath = getEnv("MPATH", "vms-3456789")
	config.VMPort = getEnv("VM_PORT", "8001")
	config.Xieyi = getEnv("XIEYI", "vms")
	config.UUID = getEnv("UUID", "3a8a1de5-7d41-45e2-88fe-0f538b822169")
	config.Youxuan = getEnv("CF_IP", "ip.sb")
	config.SubName = getEnv("SUB_NAME", "nx-app")
	config.SubURL = getEnv("SUB_URL", "")
	config.Baohuo = getEnv("BAOHUO_URL", "")
	config.NezhaServer = getEnv("NSERVER", "")
	config.NezhaKey = getEnv("NKEY", "")
	config.NezhaPort = getEnv("NPORT", "443")
	config.NezhaTLS = getEnv("NTLS", "--tls")
	config.FilePath = getEnv("FILE_PATH", "/tmp/")
	config.Tok = getEnv("TOK", "")

	if config.Tok != "" {
		config.HostName = getEnv("DOM", "")
	}

	config.NezhaHasPort = strings.Contains(config.NezhaServer, ":")

	// 生成 AGENT_UUID
	seed := config.SubName + config.UUID + config.NezhaServer + config.NezhaKey + config.Tok
	hash := sha256.Sum256([]byte(seed))
	hashStr := fmt.Sprintf("%x", hash)
	agentUUID1 := fmt.Sprintf("%s-%s-%s-%s-%s",
		hashStr[0:8], hashStr[8:12], hashStr[12:16], hashStr[16:20], hashStr[20:32])
	config.AgentUUID = getEnv("AGENT_UUID", agentUUID1)

	// 下载链接
	config.NezhaURLX64 = getEnv("NEZHA_URL_X64", "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_amd64")
	config.NezhaURLARM64 = getEnv("NEZHA_URL_ARM64", "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_arm64")
	config.NezhaURLBSD = getEnv("NEZHA_URL_BSD", "https://github.com/Fscarmon/flies/releases/latest/download/agent-freebsd_amd64")
	config.NezhaURLX64Alt = getEnv("NEZHA_URL_X64_ALT", "https://github.com/Fscarmon/flies/releases/latest/download/agent2-linux_amd64")
	config.NezhaURLARM64Alt = getEnv("NEZHA_URL_ARM64_ALT", "https://github.com/Fscarmon/flies/releases/latest/download/agent2-linux_arm64")
	config.NezhaURLBSDAlt = getEnv("NEZHA_URL_BSD_ALT", "https://github.com/Fscarmon/flies/releases/latest/download/agent2-freebsd_amd64")
	config.WebURLX64 = getEnv("WEB_URL_X64", "https://github.com/dsadsadsss/1/releases/download/xry/kano-yuan")
	config.WebURLARM64 = getEnv("WEB_URL_ARM64", "https://github.com/dsadsadsss/1/releases/download/xry/kano-yuan-arm")
	config.WebURLBSD = getEnv("WEB_URL_BSD", "https://github.com/dsadsadsss/1/releases/download/xry/kano-bsd")
	config.CFFURLX64 = getEnv("CFF_URL_X64", "https://github.com/Fscarmon/flies/releases/latest/download/cff-linux-amd64")
	config.CFFURLARM64 = getEnv("CFF_URL_ARM64", "https://github.com/Fscarmon/flies/releases/latest/download/cff-linux-arm64")
	config.CFFURLBSD = getEnv("CFF_URL_BSD", "https://github.com/dsadsadsss/1/releases/download/xry/argo-bsdamd")

	// 文件名
	config.WebFilename = getEnv("WEB_FILENAME", "webdav")
	config.NezhaFilename = getEnv("NEZHA_FILENAME", "nexus")
	config.CFFFilename = getEnv("CFF_FILENAME", "cfloat")

	// VPort
	if config.Xieyi == "vms" {
		config.VPort = config.VMPort
	} else {
		config.VPort = config.VMMPort
	}
}

// getEnv 获取环境变量
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getCountryName 获取国家名称
func getCountryName() string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://ip.xuexi365.eu.org")
	if err != nil {
		fmt.Printf("获取国家名称失败: %v\n", err)
		return "未知"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("请求失败，状态码: %d\n", resp.StatusCode)
		return "未知"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应内容失败: %v\n", err)
		return "未知"
	}

	name := strings.TrimSpace(string(body))
	if name == "" {
		fmt.Println("获取的国家名称为空")
		return "未知"
	}

	return name
}

// checkHostNameChange 检查主机名变化
func checkHostNameChange(callback func()) {
	if config.Tok == "" {
		cmd := fmt.Sprintf(`grep -oE "https://.*[a-z]+cloudflare.com" %s/argo.log | tail -n 1 | sed "s#https://##"`, config.FilePath)
		output, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			fmt.Printf("Error getting host_name: %v\n", err)
			callback()
			return
		}

		newHostName := strings.TrimSpace(string(output))
		if newHostName != "" && newHostName != lastHostName {
			fmt.Printf("host_name set to %s\n", newHostName)
			mu.Lock()
			config.HostName = newHostName
			lastHostName = newHostName
			mu.Unlock()
			buildURLs()
		}
	}
	callback()
}

// generateVmessLink 生成 Vmess 链接
func generateVmessLink() string {
	vmessConfig := VmessConfig{
		V:    "2",
		PS:   fmt.Sprintf("%s-%s", countryName, config.SubName),
		Add:  config.Youxuan,
		Port: "443",
		ID:   config.UUID,
		Aid:  "0",
		Net:  "ws",
		Type: "none",
		Host: config.HostName,
		Path: "/" + config.VMPath + "?ed=2048",
		TLS:  "tls",
		SNI:  config.HostName,
		ALPN: "",
	}

	jsonBytes, _ := json.Marshal(vmessConfig)
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonBytes)
}

// buildURLs 构建 URL
func buildURLs() {
	mu.Lock()
	defer mu.Unlock()

	if config.Xieyi == "vms" {
		upURL = generateVmessLink()
		encodedURL = upURL
	} else {
		pass := "vless"
		upURL = fmt.Sprintf("%s://%s@%s:443?path=%%2F%s%%3Fed%%3D2048&security=tls&encryption=none&host=%s&type=ws&sni=%s#%s-%s",
			pass, config.UUID, config.Youxuan, config.VMMS, config.HostName, config.HostName, countryName, config.SubName)
		encodedURL = base64.StdEncoding.EncodeToString([]byte(upURL))
	}
}

// initializeData 初始化数据
func initializeData() {
	name := getCountryName()
	if name != "" {
		countryName = name
		fmt.Printf("国家地区: %s\n", countryName)
	} else {
		fmt.Println("获取国家名称失败，使用默认值'未知'")
		countryName = "UN"
	}

	checkHostNameChange(func() {
		buildURLs()
	})
}

// sendSubscription 发送订阅
func sendSubscription() {
	if config.SubURL == "" {
		return
	}

	postData := map[string]string{
		"URL_NAME": config.SubName,
		"URL":      upURL,
	}

	jsonData, _ := json.Marshal(postData)
	resp, err := http.Post(config.SubURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Sub Upload failed")
		return
	}
	defer resp.Body.Close()

	fmt.Println("Sub Upload successful")
}

// startCronJob 启动定时任务
func startCronJob() {
	if config.Tok == "" {
		ticker := time.NewTicker(1 * time.Minute)
		go func() {
			for range ticker.C {
				checkHostNameChange(func() {
					now := time.Now().Unix()
					if now-lastSentTime >= 5*60 {
						sendSubscription()
						lastSentTime = now
					}
				})
			}
		}()
	} else {
		buildURLs()
		sendSubscription()
		ticker := time.NewTicker(1 * time.Minute)
		go func() {
			for range ticker.C {
				now := time.Now().Unix()
				if now-lastSentTime >= 5*60 {
					sendSubscription()
					lastSentTime = now
				}
			}
		}()
	}
}

// checkProcessStatus 检查进程状态
func checkProcessStatus(processName string) bool {
	cmd := fmt.Sprintf(`ps aux | grep -E "%s" | grep -v "grep"`, processName)
	output, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return false
	}
	return true
}

// checkAndStartProcess 检查并启动进程
func checkAndStartProcess(processName, startCommand string) {
	if checkProcessStatus(processName) {
		fmt.Printf("%s is already running\n", processName)
		return
	}

	cmd := exec.Command("sh", "-c", startCommand)
	if err := cmd.Start(); err != nil {
		fmt.Printf("Failed to start %s: %v\n", processName, err)
	} else {
		fmt.Printf("%s started successfully!\n", processName)
	}
}

// checkProcesses 检查所有进程
func checkProcesses() {
	if config.NezhaServer != "" && config.NezhaKey != "" {
		keepNezhaAlive()
	}
	keepCFFAlive()
	keepWebAlive()
}

// keepWebAlive 保持 Web 进程存活
func keepWebAlive() {
	processName := config.WebFilename
	startCommand := fmt.Sprintf("MPATH=%s VM_PORT=%s VPATH=%s VL_PORT=%s UUID=%s nohup %s >/dev/null 2>&1 &",
		config.VMPath, config.VMPort, config.VMMS, config.VMMPort, config.UUID,
		filepath.Join(config.FilePath, config.WebFilename))

	checkAndStartProcess(processName, startCommand)

	// 保活请求
	if spaceHost := os.Getenv("SPACE_HOST"); spaceHost != "" {
		exec.Command("curl", "-m5", "https://"+spaceHost).Run()
	} else if config.Baohuo != "" {
		exec.Command("curl", "-m5", "https://"+config.Baohuo).Run()
	} else if projectDomain := os.Getenv("PROJECT_DOMAIN"); projectDomain != "" {
		exec.Command("curl", "-m5", "https://"+projectDomain+".glitch.me").Run()
	}
}

// keepNezhaAlive 保持 Nezha 进程存活
func keepNezhaAlive() {
	processName := config.NezhaFilename
	var startCommand string

	if config.NezhaHasPort {
		startCommand = fmt.Sprintf("nohup %s -c %s >/dev/null 2>&1 &",
			filepath.Join(config.FilePath, config.NezhaFilename),
			filepath.Join(config.FilePath, "config.yml"))
	} else {
		startCommand = fmt.Sprintf("nohup %s -s %s:%s -p %s %s >/dev/null 2>&1 &",
			filepath.Join(config.FilePath, config.NezhaFilename),
			config.NezhaServer, config.NezhaPort, config.NezhaKey, config.NezhaTLS)
	}

	checkAndStartProcess(processName, startCommand)
}

// keepCFFAlive 保持 CFF 进程存活
func keepCFFAlive() {
	processName := config.CFFFilename
	var startCommand string

	if config.Tok != "" {
		startCommand = fmt.Sprintf("nohup %s tunnel --edge-ip-version auto --protocol auto --no-autoupdate run --token %s >/dev/null 2>&1 &",
			filepath.Join(config.FilePath, config.CFFFilename), config.Tok)
	} else {
		startCommand = fmt.Sprintf("nohup %s tunnel --edge-ip-version auto --protocol auto --url http://localhost:%s --no-autoupdate > %s/argo.log 2>&1 &",
			filepath.Join(config.FilePath, config.CFFFilename), config.VPort, config.FilePath)
	}

	checkAndStartProcess(processName, startCommand)
}

// startCheckingProcesses 启动进程检查定时任务
func startCheckingProcesses() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			checkProcesses()
		}
	}()
}

// downloadFile 下载文件
func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return os.Chmod(filepath, 0777)
}

// downloadWeb 下载 Web 文件
func downloadWeb(callback func(error)) {
	var webURL string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			webURL = config.WebURLX64
		} else if runtime.GOARCH == "arm64" {
			webURL = config.WebURLARM64
		}
	case "freebsd":
		webURL = config.WebURLBSD
	default:
		callback(fmt.Errorf("unsupported platform"))
		return
	}

	err := downloadFile(webURL, filepath.Join(config.FilePath, config.WebFilename))
	if err != nil {
		fmt.Println("Download web failed")
		callback(err)
	} else {
		fmt.Println("Download web successful")
		callback(nil)
	}
}

// downloadNezha 下载 Nezha 文件
func downloadNezha(callback func(error)) {
	var nezhaURL string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			if config.NezhaHasPort {
				nezhaURL = config.NezhaURLX64Alt
			} else {
				nezhaURL = config.NezhaURLX64
			}
		} else if runtime.GOARCH == "arm64" {
			if config.NezhaHasPort {
				nezhaURL = config.NezhaURLARM64Alt
			} else {
				nezhaURL = config.NezhaURLARM64
			}
		}
	case "freebsd":
		if config.NezhaHasPort {
			nezhaURL = config.NezhaURLBSDAlt
		} else {
			nezhaURL = config.NezhaURLBSD
		}
	default:
		callback(fmt.Errorf("unsupported platform"))
		return
	}

	err := downloadFile(nezhaURL, filepath.Join(config.FilePath, config.NezhaFilename))
	if err != nil {
		fmt.Println("Download nezha failed")
		callback(err)
	} else {
		fmt.Println("Download nezha successful")
		callback(nil)
	}
}

// downloadCFF 下载 CFF 文件
func downloadCFF(callback func(error)) {
	var cffURL string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			cffURL = config.CFFURLX64
		} else if runtime.GOARCH == "arm64" {
			cffURL = config.CFFURLARM64
		}
	case "freebsd":
		cffURL = config.CFFURLBSD
	default:
		callback(fmt.Errorf("unsupported platform"))
		return
	}

	err := downloadFile(cffURL, filepath.Join(config.FilePath, config.CFFFilename))
	if err != nil {
		fmt.Println("Download cff failed")
		callback(err)
	} else {
		fmt.Println("Download cff successful")
		callback(nil)
	}
}

// createNezhaConfig 创建 Nezha 配置文件
func createNezhaConfig(callback func(error)) {
	if config.NezhaServer != "" && config.NezhaHasPort {
		tlsBool := config.NezhaTLS == "--tls"
		configContent := fmt.Sprintf(`client_secret: %s
debug: false
disable_auto_update: false
disable_command_execute: false
disable_force_update: false
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 3
server: %s
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: %t
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: %s`, config.NezhaKey, config.NezhaServer, tlsBool, config.AgentUUID)

		err := os.WriteFile(filepath.Join(config.FilePath, "config.yml"), []byte(configContent), 0644)
		if err != nil {
			callback(fmt.Errorf("failed to create config.yml: %v", err))
		} else {
			fmt.Println("config.yml created successfully.")
			callback(nil)
		}
	} else {
		callback(nil)
	}
}

// initializeDownloads 初始化下载
func initializeDownloads(callback func()) {
	var wg sync.WaitGroup
	errorOccurred := false

	tasksToComplete := 2
	if config.NezhaServer != "" && config.NezhaKey != "" {
		tasksToComplete++
		if config.NezhaHasPort {
			tasksToComplete++
		}
	}

	wg.Add(tasksToComplete)

	go func() {
		downloadCFF(func(err error) {
			if err != nil {
				errorOccurred = true
			}
			wg.Done()
		})
	}()

	go func() {
		downloadWeb(func(err error) {
			if err != nil {
				errorOccurred = true
			}
			wg.Done()
		})
	}()

	if config.NezhaServer != "" && config.NezhaKey != "" {
		go func() {
			downloadNezha(func(err error) {
				if err != nil {
					errorOccurred = true
				}
				wg.Done()
			})
		}()

		if config.NezhaHasPort {
			go func() {
				createNezhaConfig(func(err error) {
					if err != nil {
						fmt.Println(err)
						errorOccurred = true
					}
					wg.Done()
				})
			}()
		}
	}

	wg.Wait()

	if errorOccurred {
		fmt.Println("Some downloads or config creation failed, but proceeding with startup.")
	} else {
		fmt.Println("All downloads and config creation successful!")
	}

	callback()
}

// upname 上传名称
func upname() {
	if config.AgentUUID == "" {
		fmt.Println("错误: AGENT_UUID 环境变量未设置")
		return
	}

	if config.NezhaServer == "" || config.NezhaKey == "" {
		return
	}

	nezURL := strings.TrimSuffix(config.NezhaServer, ":"+config.NezhaPort)
	nezURL = strings.Split(nezURL, ":")[0]
	url := fmt.Sprintf("https://%s/upload?token=%s", nezURL, config.NezhaKey)

	postData := map[string]string{
		"SUBNAME": config.SubName,
		"UUID":    config.AgentUUID,
	}

	jsonData, _ := json.Marshal(postData)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error during upname POST request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 202 {
		fmt.Println("upload sub_name succeeded")
	} else {
		fmt.Printf("upname failed with status: %d\n", resp.StatusCode)
	}
}

// setupRoutes 设置路由
func setupRoutes() {
	// 根路由
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "hello world")
	})

	// UUID 路由
	http.HandleFunc("/"+config.UUID, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, encodedURL)
	})

	// Start 路由
	http.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		type ProcessStatus struct {
			Process string  `json:"process"`
			Status  string  `json:"status"`
			Error   *string `json:"error,omitempty"`
		}

		type Response struct {
			Message   string          `json:"message"`
			Processes []ProcessStatus `json:"processes"`
		}

		processes := []struct {
			Name         string
			StartCommand string
		}{
			{
				Name: config.CFFFilename,
				StartCommand: func() string {
					if config.Tok != "" {
						return fmt.Sprintf("nohup %s tunnel --edge-ip-version auto --protocol auto run --no-autoupdate --token %s >/dev/null 2>&1 &",
							filepath.Join(config.FilePath, config.CFFFilename), config.Tok)
					}
					return fmt.Sprintf("nohup %s tunnel --edge-ip-version auto --protocol auto --url http://localhost:%s --no-autoupdate > %s/argo.log 2>&1 &",
						filepath.Join(config.FilePath, config.CFFFilename), config.VMMPort, config.FilePath)
				}(),
			},
			{
				Name: config.WebFilename,
				StartCommand: fmt.Sprintf("MPATH=%s VM_PORT=%s VPATH=%s VL_PORT=%s UUID=%s nohup %s >/dev/null 2>&1 &",
					config.VMPath, config.VMPort, config.VMMS, config.VMMPort, config.UUID,
					filepath.Join(config.FilePath, config.WebFilename)),
			},
		}

		if config.NezhaServer != "" && config.NezhaKey != "" {
			var nezhaStartCommand string
			if config.NezhaHasPort {
				nezhaStartCommand = fmt.Sprintf("nohup %s -c %s >/dev/null 2>&1 &",
					filepath.Join(config.FilePath, config.NezhaFilename),
					filepath.Join(config.FilePath, "config.yml"))
			} else {
				nezhaStartCommand = fmt.Sprintf("nohup %s -s %s:%s -p %s %s >/dev/null 2>&1 &",
					filepath.Join(config.FilePath, config.NezhaFilename),
					config.NezhaServer, config.NezhaPort, config.NezhaKey, config.NezhaTLS)
			}
			processes = append(processes, struct {
				Name         string
				StartCommand string
			}{Name: config.NezhaFilename, StartCommand: nezhaStartCommand})
		}

		var statuses []ProcessStatus
		for _, proc := range processes {
			if checkProcessStatus(proc.Name) {
				statuses = append(statuses, ProcessStatus{
					Process: proc.Name,
					Status:  "Already running",
				})
			} else {
				cmd := exec.Command("sh", "-c", proc.StartCommand)
				err := cmd.Start()
				if err != nil {
					errMsg := err.Error()
					statuses = append(statuses, ProcessStatus{
						Process: proc.Name,
						Status:  "Failed to start",
						Error:   &errMsg,
					})
				} else {
					statuses = append(statuses, ProcessStatus{
						Process: proc.Name,
						Status:  "Started",
					})
				}
			}
		}

		response := Response{
			Message:   "Process check and start completed",
			Processes: statuses,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// 代理设置
	setupProxy("/"+config.VMMS, "http://127.0.0.1:"+config.VMMPort)
	setupProxy("/"+config.VMPath, "http://127.0.0.1:"+config.VMPort)
}

// setupProxy 设置反向代理
func setupProxy(path, target string) {
	targetURL, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
}
