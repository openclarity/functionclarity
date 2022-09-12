package sign

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/openclarity/function-clarity/pkg/integrity"
	o "github.com/openclarity/function-clarity/pkg/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/spf13/viper"
)

func SignIdentity(identity string, o *o.SignBlobOptions, ro *co.RootOptions, isKeyless bool) (string, error) {
	path := "/tmp/" + uuid.New().String()
	if err := integrity.SaveTextToFile(identity, path); err != nil {
		return "", fmt.Errorf("signing identity: %w", err)
	}

	oidcClientSecret, err := o.OIDC.ClientSecret()
	if err != nil {
		return "", fmt.Errorf("signing identity: %w", err)
	}
	ko := options.KeyOpts{
		KeyRef:                   viper.GetString("privatekey"),
		PassFunc:                 generate.GetPass,
		Sk:                       o.SecurityKey.Use,
		Slot:                     o.SecurityKey.Slot,
		FulcioURL:                o.Fulcio.URL,
		IDToken:                  o.Fulcio.IdentityToken,
		InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
		RekorURL:                 o.Rekor.URL,
		OIDCIssuer:               o.OIDC.Issuer,
		OIDCClientID:             o.OIDC.ClientID,
		OIDCClientSecret:         oidcClientSecret,
		OIDCRedirectURL:          o.OIDC.RedirectURL,
		OIDCDisableProviders:     o.OIDC.DisableAmbientProviders,
		BundlePath:               o.BundlePath,
		SkipConfirmation:         o.SkipConfirmation,
	}
	outputSignature := o.OutputSignature
	outputCertificate := o.OutputCertificate
	if isKeyless {
		outputSignature = "/tmp/" + identity + ".sig"
		outputCertificate = "/tmp/" + identity + ".crt.base64"
	}

	sig, err := sign.SignBlobCmd(ro, ko, o.Registry, path, o.Base64Output, outputSignature, outputCertificate)

	if err != nil {
		return "", fmt.Errorf("signing identity: %w", err)
	}

	return string(sig), nil

}
