package mode_extract

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/utils"

	"github.com/TheManticoreProject/manticore-keycredentials/config"
	"github.com/TheManticoreProject/manticore-keycredentials/keycredential"
	kcl_utils "github.com/TheManticoreProject/manticore-keycredentials/utils"
)

// Run extracts the public key of each certificate set on a target object.
//
// The msDS-KeyCredentialLink attribute stores only the public key of a credential,
// never the certificate or the private key, so a public key is the most that can be
// recovered from the directory. Each RSA credential's public key is written to a
// file, in PEM by default or DER when requested.
//
// Parameters:
//
//	distinguishedName (string): The distinguished name of the target object.
//	outputDir (string): The directory the public keys are written to.
//	exportPem (bool): Whether to export in PEM format.
//	exportDer (bool): Whether to export in DER format.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(distinguishedName string, outputDir string, exportPem bool, exportDer bool, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'extract'")
	}

	// PEM is the default when no format is requested; the parser makes the two
	// mutually exclusive, so at most one is set here.
	extension := "pem"
	if exportDer {
		extension = "der"
	}

	ldapSession, err := kcl_utils.NewLDAPSession(
		config.Network.DomainController,
		config.Network.LDAP.LDAPPort,
		config.Credentials,
		config.Network.LDAP.UseLdaps,
		config.Network.LDAP.UseKerberos,
		config.Network.LDAP.SPNHostname,
	)
	if err != nil {
		return err
	}
	if config.Debug {
		kcl_utils.LogConnection(config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort, config.Network.LDAP.UseLdaps)
	}

	attributes := []string{"distinguishedName", "msDS-KeyCredentialLink", "sAMAccountName"}
	entry, err := kcl_utils.FindUniqueObject(ldapSession, distinguishedName, attributes, config.Debug)
	if err != nil {
		return err
	}

	rawValues := entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink")
	if len(rawValues) == 0 {
		logger.Print(fmt.Sprintf("[>] Public keys extracted from \x1b[94m%s\x1b[0m (0)", distinguishedName))
		return nil
	}

	// The public keys of one object go into a single directory named after it, so
	// running extract against several objects does not mix their keys together. The
	// account name is used rather than the full distinguished name to keep the path
	// short and free of commas and equals signs.
	dirName := utils.PathSafeString(entry.GetAttributeValue("sAMAccountName"))
	if len(dirName) == 0 {
		dirName = utils.PathSafeString(distinguishedName)
	}
	targetDir := filepath.Join(outputDir, dirName)

	exported := []string{}
	for k, rawValue := range rawValues {
		kc, err := keycredential.ParseValue(rawValue)
		if err != nil {
			logger.Warn(fmt.Sprintf("Skipping value %d/%d, %s", k+1, len(rawValues), err))
			continue
		}

		rsaKeyMaterial, ok := keycredential.RSAKeyMaterial(kc)
		if !ok {
			logger.Warn(fmt.Sprintf("Skipping value %d/%d, key material is %T and not an RSA public key", k+1, len(rawValues), kc.KeyMaterial))
			continue
		}

		var data []byte
		if exportDer {
			data, err = rsaKeyMaterial.ExportDER()
		} else {
			data, err = rsaKeyMaterial.ExportPEM()
		}
		if err != nil {
			return fmt.Errorf("error exporting public key of value %d/%d: %s", k+1, len(rawValues), err)
		}

		path := filepath.Join(targetDir, fmt.Sprintf("%03d.pub.%s", k+1, extension))
		if err := writeFile(path, data); err != nil {
			return err
		}
		exported = append(exported, path)
	}

	if len(exported) == 0 {
		logger.Print(fmt.Sprintf("[>] Public keys extracted from \x1b[94m%s\x1b[0m (0)", distinguishedName))
		return nil
	}

	logger.Print(fmt.Sprintf("[>] Public keys extracted from \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m):", distinguishedName, len(exported)))
	for k, path := range exported {
		if k < len(exported)-1 {
			logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m", path))
		} else {
			logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m", path))
		}
	}
	logger.Print("")

	return nil
}

// writeFile writes data to path, creating the parent directory if needed. A public
// key is not secret, so the default modes are appropriate here.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("error creating output directory: %s", err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("error writing '%s': %s", path, err)
	}
	return nil
}
