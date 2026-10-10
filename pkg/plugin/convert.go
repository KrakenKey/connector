package plugin

import (
	"time"

	pb "github.com/krakenkey/connector/proto/krakenkey/connector/plugin/v1"
)

var keyTypeToPB = map[KeyType]pb.KeyType{
	KeyTypeECDSAP256: pb.KeyType_KEY_TYPE_ECDSA_P256,
	KeyTypeECDSAP384: pb.KeyType_KEY_TYPE_ECDSA_P384,
	KeyTypeRSA2048:   pb.KeyType_KEY_TYPE_RSA_2048,
	KeyTypeRSA3072:   pb.KeyType_KEY_TYPE_RSA_3072,
	KeyTypeRSA4096:   pb.KeyType_KEY_TYPE_RSA_4096,
}

var keyFormatToPB = map[KeyFormat]pb.KeyFormat{
	KeyFormatVaultRef: pb.KeyFormat_KEY_FORMAT_VAULT_REF,
	KeyFormatPEM:      pb.KeyFormat_KEY_FORMAT_PEM,
	KeyFormatPFX:      pb.KeyFormat_KEY_FORMAT_PFX,
}

func pbKeyType(k KeyType) pb.KeyType {
	return keyTypeToPB[k] // unknown maps to UNSPECIFIED
}

func goKeyType(k pb.KeyType) KeyType {
	for g, p := range keyTypeToPB {
		if p == k {
			return g
		}
	}
	return ""
}

func pbKeyTypes(ks []KeyType) []pb.KeyType {
	out := make([]pb.KeyType, 0, len(ks))
	for _, k := range ks {
		if p := pbKeyType(k); p != pb.KeyType_KEY_TYPE_UNSPECIFIED {
			out = append(out, p)
		}
	}
	return out
}

// goKeyTypes drops values this version does not know, so a newer plugin
// cannot make the core match on a key type it cannot name.
func goKeyTypes(ks []pb.KeyType) []KeyType {
	out := make([]KeyType, 0, len(ks))
	for _, k := range ks {
		if g := goKeyType(k); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func pbFormat(f KeyFormat) pb.KeyFormat { return keyFormatToPB[f] }

func goFormat(f pb.KeyFormat) KeyFormat {
	for g, p := range keyFormatToPB {
		if p == f {
			return g
		}
	}
	return ""
}

func pbFormats(fs []KeyFormat) []pb.KeyFormat {
	out := make([]pb.KeyFormat, 0, len(fs))
	for _, f := range fs {
		if p := pbFormat(f); p != pb.KeyFormat_KEY_FORMAT_UNSPECIFIED {
			out = append(out, p)
		}
	}
	return out
}

func goFormats(fs []pb.KeyFormat) []KeyFormat {
	out := make([]KeyFormat, 0, len(fs))
	for _, f := range fs {
		if g := goFormat(f); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func pbKeyMaterial(k KeyMaterial) *pb.KeyMaterial {
	if k.Format == "" && len(k.Data) == 0 && k.Ref == "" && k.Password == "" {
		return nil
	}
	return &pb.KeyMaterial{Format: pbFormat(k.Format), Data: k.Data, Ref: k.Ref, Password: k.Password}
}

func goKeyMaterial(k *pb.KeyMaterial) KeyMaterial {
	if k == nil {
		return KeyMaterial{}
	}
	return KeyMaterial{Format: goFormat(k.GetFormat()), Data: k.GetData(), Ref: k.GetRef(), Password: k.GetPassword()}
}

func pbKeyStoreCaps(c KeyStoreCapabilities) *pb.KeyStoreCapabilities {
	return &pb.KeyStoreCapabilities{
		Provides:   pbFormats(c.Provides),
		Exportable: c.Exportable,
		KeyTypes:   pbKeyTypes(c.KeyTypes),
	}
}

func goKeyStoreCaps(c *pb.KeyStoreCapabilities) KeyStoreCapabilities {
	return KeyStoreCapabilities{
		Provides:   goFormats(c.GetProvides()),
		Exportable: c.GetExportable(),
		KeyTypes:   goKeyTypes(c.GetKeyTypes()),
	}
}

func pbTargetCaps(c TargetCapabilities) *pb.TargetCapabilities {
	return &pb.TargetCapabilities{
		Accepts:                    pbFormats(c.Accepts),
		NeedsExportableKey:         c.NeedsExportableKey,
		SupportsRollback:           c.SupportsRollback,
		KeyTypes:                   pbKeyTypes(c.KeyTypes),
		DefaultVerifyWindowSeconds: int64(c.DefaultVerifyWindow / time.Second),
		PropagatesAsync:            c.PropagatesAsync,
		RollbackNeedsMaterial:      c.RollbackNeedsMaterial,
	}
}

func goTargetCaps(c *pb.TargetCapabilities) TargetCapabilities {
	return TargetCapabilities{
		Accepts:             goFormats(c.GetAccepts()),
		NeedsExportableKey:  c.GetNeedsExportableKey(),
		SupportsRollback:    c.GetSupportsRollback(),
		KeyTypes:            goKeyTypes(c.GetKeyTypes()),
		DefaultVerifyWindow: time.Duration(c.GetDefaultVerifyWindowSeconds()) * time.Second,
		PropagatesAsync:       c.GetPropagatesAsync(),
		RollbackNeedsMaterial: c.GetRollbackNeedsMaterial(),
	}
}
