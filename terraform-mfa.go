package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	ini "gopkg.in/ini.v1"
)

// Global Variables
var version = "0.0.1"

// AWSConfig stores AWS shared config data
type AWSConfig struct {
	profile string
	role    string
	mfa     string
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "This is not helpful.\n")
		flag.PrintDefaults()
		return
	}
	profilePtr := flag.String("profile", "default", "AWS Profile to use")
	versionPtr := flag.Bool("version", false, "Display version")
	flag.Parse()
	// Display version and exit
	if *versionPtr {
		fmt.Printf("Terraform MFA Wrapper v%s\n", version)
		return
	}
	// Parse the AWS shared config
	awscfg := GetAWSConfig(*profilePtr)
	if awscfg == nil {
		fmt.Printf("Unable to retrieve information from AWS shares config\n")
		os.Exit(1)
	}
	// Get MFA Code
	fmt.Printf("Enter MFA Code: ")
	var otp string
	fmt.Scanln(&otp)
	fmt.Printf("\n")
	// Assume Role
	svc := sts.New(CreateSession(awscfg.profile))
	input := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(180),
		RoleArn:         aws.String(awscfg.role),
		SerialNumber:    aws.String(awscfg.mfa),
		TokenCode:       aws.String(otp),
		RoleSessionName: aws.String("terraform"),
	}
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
		os.Exit(1)
	}
	// Run Terraform
	os.Setenv("AWS_ACCESS_KEY_ID", *result.Credentials.AccessKeyId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", *result.Credentials.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", *result.Credentials.SessionToken)
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_SESSION_TOKEN")
	out, _ := exec.Command("terraform", flag.Args()...).CombinedOutput()
	fmt.Println(string(out))
}

// GetAWSConfig parses the AWS shared config and returns an AWSConfig struct
func GetAWSConfig(profile string) *AWSConfig {
	var home string
	// Set home directory based off OS, untested on Windows
	if runtime.GOOS == "windows" {
		home = os.Getenv("USERPROFILE")
	} else {
		home = os.Getenv("HOME")
	}
	// Try an additional env variable and possibly accept user input for .aws location
	// Check credentials file
	cfg, err := ini.Load(home + "/.aws/config")
	if err != nil {
		fmt.Printf("Message: There was an error loading the AWS shared config\nError: %s\n", err)
		return nil
	}
	profile = "profile " + profile
	r := AWSConfig{
		profile: cfg.Section(profile).Key("source_profile").String(),
		role:    cfg.Section(profile).Key("role_arn").String(),
		mfa:     cfg.Section(profile).Key("mfa_serial").String(),
	}
	return &r
}

// CreateSession creates an aws sdk session
func CreateSession(profile string) *session.Session {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Profile:           profile,
	}))
	return sess
}
