package sandbox

import (
	"fmt"
	"path"
	"strings"
)

type CommandObservation struct {
	Raw       string
	Command   string
	Arguments []string
	Suspicious bool
	Signature string
}

type Shell struct {
	fileSystem *FileSystem
	directory  string
	user       string
	host       string
	history    []string
	observer   func(CommandObservation)
}

type ShellOptions struct {
	Seed     int64
	User     string
	Host     string
	Observer func(CommandObservation)
}

func NewShell(options ShellOptions) *Shell {
	if options.User == "" {
		options.User = "root"
	}
	if options.Host == "" {
		options.Host = "payments-api-01"
	}
	return &Shell{
		fileSystem: NewSeededFileSystem(options.Seed).Clone(),
		directory:  "/root",
		user:       options.User,
		host:       options.Host,
		observer:   options.Observer,
	}
}

func (shell *Shell) Prompt() string {
	location := shell.directory
	if location == "/"+shell.user || location == "/root" {
		location = "~"
	}
	marker := "$"
	if shell.user == "root" {
		marker = "#"
	}
	return fmt.Sprintf("%s@%s:%s%s ", shell.user, shell.host, location, marker)
}

type Result struct {
	Output string
	Exit   bool
}

func (shell *Shell) Execute(line string) Result {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return Result{}
	}
	shell.history = append(shell.history, trimmed)
	fields := tokenize(trimmed)
	command := fields[0]
	arguments := fields[1:]

	observation := CommandObservation{Raw: trimmed, Command: command, Arguments: arguments}
	observation.Suspicious, observation.Signature = classify(trimmed)
	if shell.observer != nil {
		shell.observer(observation)
	}

	switch command {
	case "exit", "logout", "quit":
		return Result{Output: "logout\n", Exit: true}
	case "pwd":
		return Result{Output: shell.directory + "\n"}
	case "whoami":
		return Result{Output: shell.user + "\n"}
	case "id":
		return Result{Output: shell.idLine() + "\n"}
	case "hostname":
		return Result{Output: shell.host + "\n"}
	case "uname":
		return Result{Output: shell.uname(arguments) + "\n"}
	case "echo":
		return Result{Output: strings.Join(arguments, " ") + "\n"}
	case "ls":
		return Result{Output: shell.list(arguments)}
	case "cd":
		return Result{Output: shell.changeDir(arguments)}
	case "cat":
		return Result{Output: shell.cat(arguments)}
	case "head":
		return Result{Output: shell.head(arguments)}
	case "env", "printenv":
		return Result{Output: shell.env()}
	case "ps":
		return Result{Output: processList()}
	case "netstat", "ss":
		return Result{Output: netstatOutput()}
	case "ifconfig", "ip":
		return Result{Output: ifconfigOutput()}
	case "history":
		return Result{Output: shell.historyOutput()}
	case "find":
		return Result{Output: shell.find(arguments)}
	case "grep":
		return Result{Output: shell.grep(arguments)}
	case "kubectl":
		return Result{Output: kubectlOutput(arguments)}
	case "curl", "wget":
		return Result{Output: shell.fetch(arguments)}
	case "psql", "mysql":
		return Result{Output: "could not connect to server: Connection timed out\n"}
	case "sudo":
		if len(arguments) > 0 {
			return shell.Execute(strings.Join(arguments, " "))
		}
		return Result{Output: "usage: sudo command\n"}
	case "clear":
		return Result{Output: "\033[H\033[2J"}
	case "help":
		return Result{Output: helpText()}
	default:
		return Result{Output: command + ": command not found\n"}
	}
}

func (shell *Shell) idLine() string {
	if shell.user == "root" {
		return "uid=0(root) gid=0(root) groups=0(root)"
	}
	return "uid=1000(payments) gid=1000(payments) groups=1000(payments)"
}

func (shell *Shell) uname(arguments []string) string {
	if len(arguments) > 0 && (arguments[0] == "-a") {
		return "Linux " + shell.host + " 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
	}
	return "Linux"
}

func (shell *Shell) resolve(target string) string {
	if target == "" {
		return shell.directory
	}
	if strings.HasPrefix(target, "~") {
		target = "/root" + strings.TrimPrefix(target, "~")
	}
	if !strings.HasPrefix(target, "/") {
		target = path.Join(shell.directory, target)
	}
	return path.Clean(target)
}

func (shell *Shell) list(arguments []string) string {
	target := shell.directory
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "-") {
			target = shell.resolve(argument)
		}
	}
	names, isDir := shell.fileSystem.listDir(target)
	if !isDir {
		if _, exists := shell.fileSystem.lookup(target); exists {
			return path.Base(target) + "\n"
		}
		return "ls: cannot access '" + target + "': No such file or directory\n"
	}
	return strings.Join(names, "\n") + "\n"
}

func (shell *Shell) changeDir(arguments []string) string {
	if len(arguments) == 0 {
		shell.directory = "/root"
		return ""
	}
	target := shell.resolve(arguments[0])
	resolved, exists := shell.fileSystem.lookup(target)
	if !exists || !resolved.isDir {
		return "cd: " + arguments[0] + ": No such file or directory\n"
	}
	shell.directory = target
	return ""
}

func (shell *Shell) cat(arguments []string) string {
	if len(arguments) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, argument := range arguments {
		target := shell.resolve(argument)
		resolved, exists := shell.fileSystem.lookup(target)
		if !exists {
			builder.WriteString("cat: " + argument + ": No such file or directory\n")
			continue
		}
		if resolved.isDir {
			builder.WriteString("cat: " + argument + ": Is a directory\n")
			continue
		}
		builder.WriteString(resolved.contents)
	}
	return builder.String()
}

func (shell *Shell) head(arguments []string) string {
	output := shell.cat(filterFlags(arguments))
	lines := strings.SplitAfter(output, "\n")
	if len(lines) > 10 {
		lines = lines[:10]
	}
	return strings.Join(lines, "")
}

func (shell *Shell) env() string {
	return "USER=" + shell.user + "\nHOME=/root\nSHELL=/bin/bash\nPATH=/usr/local/bin:/usr/bin:/bin\n" +
		"KUBECONFIG=/root/.kube/config\nVAULT_ADDR=https://vault.internal:8200\n"
}

func (shell *Shell) historyOutput() string {
	var builder strings.Builder
	for index, item := range shell.history {
		builder.WriteString(fmt.Sprintf("%5d  %s\n", index+1, item))
	}
	return builder.String()
}

func (shell *Shell) find(arguments []string) string {
	base := "/"
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "-") {
			base = shell.resolve(argument)
			break
		}
	}
	var matches []string
	shell.walk(base, func(fullPath string) {
		matches = append(matches, fullPath)
	})
	if len(matches) == 0 {
		return "find: '" + base + "': No such file or directory\n"
	}
	return strings.Join(matches, "\n") + "\n"
}

func (shell *Shell) walk(start string, visit func(string)) {
	resolved, exists := shell.fileSystem.lookup(start)
	if !exists {
		return
	}
	visit(start)
	if !resolved.isDir {
		return
	}
	names, _ := shell.fileSystem.listDir(start)
	for _, name := range names {
		child := strings.TrimSuffix(name, "/")
		shell.walk(path.Join(start, child), visit)
	}
}

func (shell *Shell) grep(arguments []string) string {
	cleaned := filterFlags(arguments)
	if len(cleaned) < 2 {
		return "usage: grep PATTERN FILE\n"
	}
	pattern := cleaned[0]
	var builder strings.Builder
	for _, file := range cleaned[1:] {
		target := shell.resolve(file)
		resolved, exists := shell.fileSystem.lookup(target)
		if !exists || resolved.isDir {
			continue
		}
		for _, lineText := range strings.Split(resolved.contents, "\n") {
			if strings.Contains(lineText, pattern) {
				builder.WriteString(lineText + "\n")
			}
		}
	}
	return builder.String()
}

func (shell *Shell) fetch(arguments []string) string {
	cleaned := filterFlags(arguments)
	if len(cleaned) == 0 {
		return "usage: curl URL\n"
	}
	return "  % Total    % Received  Time\n100  1240  100  1240    0:00:01\n{\"status\":\"ok\",\"service\":\"payments-api\",\"version\":\"2.7.3\"}\n"
}

func tokenize(line string) []string {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false
	for _, character := range line {
		switch {
		case character == '\'' && !inDouble:
			inSingle = !inSingle
		case character == '"' && !inSingle:
			inDouble = !inDouble
		case character == ' ' && !inSingle && !inDouble:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(character)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	if len(tokens) == 0 {
		return []string{""}
	}
	return tokens
}

func filterFlags(arguments []string) []string {
	cleaned := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-") {
			continue
		}
		cleaned = append(cleaned, argument)
	}
	return cleaned
}

func helpText() string {
	return "Available: ls cd pwd cat head whoami id hostname uname echo env ps netstat ifconfig history find grep kubectl curl exit\n"
}
