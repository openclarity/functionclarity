package sign

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/openclarity/function-clarity/pkg/integrity"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
)

func SignIdentity(identity string, o *co.SignBlobOptions, ro *co.RootOptions) (string, error) {
	path := "/tmp/" + uuid.New().String()
	if err := integrity.SaveTextToFile(identity, path); err != nil {
		return "", err
	}

	oidcClientSecret, err := o.OIDC.ClientSecret()
	if err != nil {
		return "", err
	}
	ko := options.KeyOpts{
		KeyRef:                   o.Key,
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
	sig, err := sign.SignBlobCmd(ro, ko, o.Registry, path, o.Base64Output, o.OutputSignature, o.OutputCertificate)

	if err != nil {
		return "", fmt.Errorf("signing identity: %s, %w", identity, err)
	}

	return string(sig), nil

}
