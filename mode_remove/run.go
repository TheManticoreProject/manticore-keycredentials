package mode_remove

import (
	"crypto/rsa"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"

	"github.com/TheManticoreProject/manticore-keycredentials/certificate"
	"github.com/TheManticoreProject/manticore-keycredentials/cli"
	"github.com/TheManticoreProject/manticore-keycredentials/config"
	"github.com/TheManticoreProject/manticore-keycredentials/keycredential"
	"github.com/TheManticoreProject/manticore-keycredentials/utils"
)

// plan is what would change on one target object: the raw values matched for
// removal, and how many values are left untouched.
type plan struct {
	distinguishedName string
	removed           []string
	kept              int
}

// Run removes a single specified certificate from one or more target objects.
//
// The certificate is identified by its public key, so every key credential on a
// target whose key material matches is removed. Values that cannot be parsed or are
// not RSA are left untouched, so an unrecognised credential is never dropped as a
// side effect.
//
// Parameters:
//
//	targets (cli.TargetOptions): The target selection flags.
//	safety (cli.SafetyOptions): The dry-run and confirmation flags.
//	pfxCertificate (string): Path to a PFX file holding the certificate to remove.
//	pfxPassword (string): Password of the PFX file.
//	pemFile (string): Path to a PEM file holding the certificate to remove.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, or if any target could not be modified.
func Run(targets cli.TargetOptions, safety cli.SafetyOptions, pfxCertificate, pfxPassword, pemFile string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'remove'")
	}

	var publicKey *rsa.PublicKey
	var err error
	if len(pfxCertificate) > 0 {
		publicKey, err = certificate.LoadRSAPublicKeyFromPFX(pfxCertificate, pfxPassword)
	} else {
		publicKey, err = certificate.LoadRSAPublicKeyFromPEM(pemFile)
	}
	if err != nil {
		return err
	}
	wantedFingerprint := keycredential.FingerprintRSAPublicKey(publicKey)
	if config.Debug {
		logger.Debug(fmt.Sprintf("Removing key fingerprint: %s", wantedFingerprint))
	}

	if err := cli.ValidateTargets(targets); err != nil {
		return err
	}

	ldapSession, err := utils.NewLDAPSession(
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
		utils.LogConnection(config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort, config.Network.LDAP.UseLdaps)
	}

	attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
	entries, err := cli.ResolveTargets(ldapSession, targets, attributes, config.Debug)
	if err != nil {
		return err
	}

	// Work out, per object, which raw values match and which stay, without changing
	// anything yet.
	plans := []plan{}
	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")
		p := plan{distinguishedName: dn}
		for _, rawValue := range entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink") {
			kc, err := keycredential.ParseValue(rawValue)
			if err != nil {
				// An unparsable value cannot be identified, so it is kept.
				p.kept++
				continue
			}
			fingerprint, ok := keycredential.Fingerprint(kc)
			if ok && fingerprint == wantedFingerprint {
				// The exact server-returned value is deleted, so removing the last
				// matching value clears the attribute instead of leaving an empty
				// replace that the directory rejects.
				p.removed = append(p.removed, string(rawValue))
				continue
			}
			p.kept++
		}
		if len(p.removed) > 0 {
			plans = append(plans, p)
		}
	}

	logger.Print(fmt.Sprintf("[>] Objects the certificate would be removed from (\x1b[93m%d\x1b[0m of %d resolved):", len(plans), len(entries)))
	for k, p := range plans {
		glyph := "├──"
		if k == len(plans)-1 {
			glyph = "└──"
		}
		logger.Print(fmt.Sprintf("  %s \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m to remove, \x1b[93m%d\x1b[0m kept)", glyph, p.distinguishedName, len(p.removed), p.kept))
	}
	logger.Print("")

	if len(plans) == 0 {
		logger.Info("The certificate was not found on any resolved target; nothing to remove.")
		return nil
	}

	if !cli.ConfirmWrite("remove the certificate from", len(plans), safety) {
		return nil
	}

	failures := 0
	for _, p := range plans {
		err := ldapSession.Modify(&ldap.ModifyRequest{
			DistinguishedName: p.distinguishedName,
			Attributes: []*ldap.Action{
				{
					Attribute: "msDS-KeyCredentialLink",
					DelValues: p.removed,
				},
			},
		})
		if err != nil {
			failures++
			logger.Warn(fmt.Sprintf("%s: %s", p.distinguishedName, err))
			continue
		}
		logger.Info(fmt.Sprintf("Removed %d value(s) from '%s'", len(p.removed), p.distinguishedName))
	}

	if failures > 0 {
		return fmt.Errorf("failed to modify %d of %d object(s)", failures, len(plans))
	}

	return nil
}
