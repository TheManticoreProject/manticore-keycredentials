package mode_create

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/utils"

	"github.com/TheManticoreProject/manticore-keycredentials/certificate"
	"github.com/TheManticoreProject/manticore-keycredentials/config"
)

// adFlags are the flags create used to accept when it wrote to Active Directory.
// It no longer does, so their presence is a sign the caller expects the old
// behaviour and is redirected to enroll rather than silently getting a local-only
// certificate and no directory change.
var adFlags = map[string]bool{
	"-D": true, "--distinguished-name": true,
	"-dc": true, "--dc-ip": true,
	"-lp": true, "--ldap-port": true,
	"-L": true, "--use-ldaps": true,
	"-k": true, "--use-kerberos": true,
	"--dns-name-server": true,
	"-d":                true, "--domain": true,
	"-u": true, "--username": true,
	"-p": true, "--password": true,
	"-H": true, "--hashes": true,
	"--no-pass": true, "--aes-key": true,
}

// Run creates a new certificate and saves its private key and certificate locally.
//
// This mode does not talk to Active Directory. To create a certificate and attach
// it to a target object, use enroll.
//
// Parameters:
//
//	subject (string): The common name of the generated certificate.
//	notBefore (string): The start of the certificate validity window.
//	notAfter (string): The end of the certificate validity window.
//	keySize (int): The RSA key size.
//	outputDir (string): The directory the files are written to.
//	pfxPassword (string): The PFX password, or empty for a random one.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(subject, notBefore, notAfter string, keySize int, outputDir, pfxPassword string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'create'")
	}

	if offending := adFlagsInArgs(os.Args); len(offending) > 0 {
		return fmt.Errorf("create no longer writes to Active Directory, it generates a certificate locally; the flag(s) %s belong to 'enroll', which creates and attaches a credential to a target object", strings.Join(offending, ", "))
	}

	notBeforeTime, notAfterTime, err := certificate.ParseValidityWindow(notBefore, notAfter)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Creating new certificate for subject '%s'", subject))
	cert, err := certificate.Generate(subject, keySize, notBeforeTime, notAfterTime)
	if err != nil {
		return err
	}

	if len(pfxPassword) == 0 {
		pfxPassword = utils.RandomString(16)
	}

	datePrefix := time.Now().Format("2006-01-02_15-04-05")
	baseName := utils.PathSafeString(subject)
	// Reserve the directory rather than just naming it: the timestamp has one-second
	// resolution, so a concurrent or immediately repeated run would otherwise share it
	// and overwrite this run's private key.
	dir, err := certificate.ReserveOutputDir(outputDir, datePrefix)
	if err != nil {
		return err
	}

	filePrivateKey := filepath.Join(dir, baseName+".pem")
	fileCertificate := filepath.Join(dir, baseName+".cert.pem")
	filePFX := filepath.Join(dir, fmt.Sprintf("%s_%s.pfx", baseName, pfxPassword))

	if err := cert.ExportRSAPrivateKeyPEM(filePrivateKey); err != nil {
		return fmt.Errorf("error exporting PEM private key: %s", err)
	}
	if err := cert.ExportCertificatePEM(fileCertificate); err != nil {
		return fmt.Errorf("error exporting PEM certificate: %s", err)
	}
	if err := cert.ExportPFX(filePFX, pfxPassword); err != nil {
		return fmt.Errorf("error exporting PFX certificate: %s", err)
	}

	logger.Print(fmt.Sprintf("[>] Created a new certificate for \x1b[94m%s\x1b[0m:", subject))
	logger.Print(fmt.Sprintf("  ├── Private key (PEM): \x1b[94m%s\x1b[0m", filePrivateKey))
	logger.Print(fmt.Sprintf("  ├── Certificate (PEM): \x1b[94m%s\x1b[0m", fileCertificate))
	logger.Print(fmt.Sprintf("  └── PFX (password '\x1b[93m%s\x1b[0m'): \x1b[94m%s\x1b[0m", pfxPassword, filePFX))
	logger.Print("")
	logger.Info("Attach it to a target object with 'attach', which takes an existing certificate:")
	logger.Info(fmt.Sprintf("   manticore-keycredentials attach --pfx '%s' --pfx-password '%s' -D '<target DN>' -dc <dc-ip> -d <domain> -u <user> -p <password>", filePFX, pfxPassword))

	return nil
}

// adFlagsInArgs returns the Active-Directory flags present in the argument list,
// so the caller can be told which ones no longer apply to create.
//
// The `--flag=value` form is handled by comparing only the part before the '='.
//
// Parameters:
//
//	args ([]string): The process arguments, including the program name and mode.
//
// Returns:
//
//	The offending flags, in the order they appear, with no duplicates.
func adFlagsInArgs(args []string) []string {
	seen := map[string]bool{}
	offending := []string{}
	// Skip the program name and the mode selector.
	start := 2
	if len(args) < start {
		start = len(args)
	}
	for _, arg := range args[start:] {
		flag := arg
		if i := strings.IndexByte(flag, '='); i >= 0 {
			flag = flag[:i]
		}
		if adFlags[flag] && !seen[flag] {
			seen[flag] = true
			offending = append(offending, flag)
		}
	}
	return offending
}
