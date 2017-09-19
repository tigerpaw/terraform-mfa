package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	ini "gopkg.in/ini.v1"
)

// Global Variables
var version = "0.1.1"

// AWSConfig stores AWS shared config data
type AWSConfig struct {
	profile string
	role    string
	mfa     string
}

func main() {
	profilePtr := flag.String("profile", "default", "AWS Profile to use")
	versionPtr := flag.Bool("version", false, "Display version")
	// Customize flag.Usage
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"Usage: %s [--help] [--version] [--profile aws_profile] <command> [args]\n\n",
			filepath.Base(os.Args[0]),
		)
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()
	// Display version and exit
	if *versionPtr {
		fmt.Printf("Terraform MFA Wrapper v%s\n", version)
		return
	}
	// Check if we need to authenticate to AWS to run the command
	authreq := map[string]bool{
		"apply":   true,
		"destroy": true,
		"plan":    true,
	}
	if authreq[flag.Arg(0)] {
		// Parse the AWS shared config
		awscfg := GetAWSConfig(*profilePtr)
		if awscfg == nil {
			return
		}
		// Get MFA Code
		var input string
		fmt.Printf("Enter MFA Code: ")
		fmt.Scanln(&input)
		fmt.Printf("\n")
		// Assume Role
		result, err := AssumeRole(
			&sts.AssumeRoleInput{
				DurationSeconds: aws.Int64(900), // Minimum field value is 900
				RoleArn:         aws.String(awscfg.role),
				SerialNumber:    aws.String(awscfg.mfa),
				TokenCode:       aws.String(input),
				RoleSessionName: aws.String("terraform"),
			},
			sts.New(CreateSession(awscfg.profile)),
		)
		if err != nil {
			fmt.Printf("Message: Unable to assume role\nError: %s", err)
			return
		}
		// Set environment variables
		os.Setenv("AWS_ACCESS_KEY_ID", *result.Credentials.AccessKeyId)
		os.Setenv("AWS_SECRET_ACCESS_KEY", *result.Credentials.SecretAccessKey)
		os.Setenv("AWS_SESSION_TOKEN", *result.Credentials.SessionToken)
		// Unset environment variables
		defer os.Unsetenv("AWS_ACCESS_KEY_ID")
		defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
		defer os.Unsetenv("AWS_SESSION_TOKEN")
	}
	// Run Terraform
	out, _ := exec.Command("terraform", flag.Args()...).CombinedOutput()
	fmt.Println(string(out))
}

// GetAWSConfig parses the AWS shared config and returns an AWSConfig struct
func GetAWSConfig(profile string) *AWSConfig {
	var home, path, f string
	// Check if user has AWS_CONFIG_FILE set
	if os.Getenv("AWS_CONFIG_FILE") == "" {
		// Try to figure out the location based on OS, untested on Windows
		if runtime.GOOS == "windows" {
			home, path = os.Getenv("USERPROFILE"), "\\.aws\\config" // Untested
		} else {
			home, path = os.Getenv("HOME"), "/.aws/config"
		}
		if home != "" {
			f = home + path
		} else {
			var input string
			fmt.Printf("Please enter the full path to your aws shared config file\nPath: ")
			fmt.Scanln(&input)
			fmt.Println("\nYou can also set this value to the AWS_CONFIG_FILE environment variable")
			f = input
		}
	} else {
		f = os.Getenv("AWS_CONFIG_FILE")
	}
	// Check to make sure the file we want to load actually exists
	if _, err := os.Stat(f); os.IsNotExist(err) {
		fmt.Printf("Bad path: %s", f)
		return nil
	}
	// Check credentials file
	cfg, err := ini.Load(f)
	if err != nil {
		fmt.Printf("Message: There was an error loading the AWS shared config\nError: %s\n", err)
		return nil
	}
	if profile != "default" {
		profile = "profile " + profile
	}
	// Check if the supplied profile is valid
	if _, err := cfg.GetSection(profile); err != nil {
		fmt.Printf("No such profile \"%s\" in \"%s\"\n", strings.TrimPrefix(profile, "profile "), f)
		return nil
	}
	r := AWSConfig{
		profile: cfg.Section(profile).Key("source_profile").String(),
		role:    cfg.Section(profile).Key("role_arn").String(),
		mfa:     cfg.Section(profile).Key("mfa_serial").String(),
	}
	return &r
}

// AssumeRole assumes an AWS role
func AssumeRole(input *sts.AssumeRoleInput, svc *sts.STS) (*sts.AssumeRoleOutput, error) {
	result, err := svc.AssumeRole(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case sts.ErrCodeMalformedPolicyDocumentException:
				fmt.Println(sts.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case sts.ErrCodePackedPolicyTooLargeException:
				fmt.Println(sts.ErrCodePackedPolicyTooLargeException, aerr.Error())
			case sts.ErrCodeRegionDisabledException:
				fmt.Println(sts.ErrCodeRegionDisabledException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		return nil, err
	}
	return result, nil
}

// CreateSession creates an AWS SDK session
func CreateSession(profile string) *session.Session {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Profile:           profile,
	}))
	return sess
}
