package goquic

// #include "src/adaptor.h"
// #include "src/go_structs.h"
import "C"
import "unsafe"

// Serialized server config
type SerializedServerConfig struct {
	ServerConfig []byte
	Keys         []*ServerConfigPrivateKey
}

type ServerConfigPrivateKey struct {
	Key []byte
	Tag uint32
}

// Wrapper for QuicCryptoServerConfig C++ object
type QuicCryptoServerConfig struct {
	cryptoServerConfig unsafe.Pointer
}

func NewCryptoServerConfig(proofSource *ProofSource, stkSecret string, cfg *SerializedServerConfig) *QuicCryptoServerConfig {
	serverCfg_c := C.create_goquic_crypto_config((*C.char)(unsafe.Pointer(&cfg.ServerConfig[0])), C.size_t(len(cfg.ServerConfig)), C.int(len(cfg.Keys)))
	defer C.delete_goquic_crypto_config(serverCfg_c)

	for idx, key := range cfg.Keys {
		C.goquic_crypto_config_set_key(serverCfg_c, C.int(idx), C.uint32_t(key.Tag), (*C.char)(unsafe.Pointer(&key.Key[0])), C.size_t(len(key.Key)))
	}
	cryptoConfig_c := C.init_crypto_config(serverCfg_c, proofSource.proofSource_c, (*C.char)(unsafe.Pointer(&[]byte(stkSecret)[0])), C.size_t(len(stkSecret)))

	return &QuicCryptoServerConfig{cryptoConfig_c}
}

func DeleteCryptoServerConfig(config *QuicCryptoServerConfig) {
	C.delete_crypto_config(config.cryptoServerConfig)
}

func GenerateSerializedServerConfig() *SerializedServerConfig {
	serverCfg_c := C.generate_goquic_crypto_config()
	defer C.delete_goquic_crypto_config(serverCfg_c)

	r := &SerializedServerConfig{}
	N := int(serverCfg_c.Num_of_keys)

	r.ServerConfig = C.GoBytes(unsafe.Pointer((*C.char)(serverCfg_c.Server_config)), serverCfg_c.Server_config_len)
	r.Keys = make([]*ServerConfigPrivateKey, N)

	tagsArray := (*[1 << 30]C.uint32_t)(unsafe.Pointer(serverCfg_c.Private_keys_tag))[:N:N]
	lenArray := (*[1 << 30]C.int)(unsafe.Pointer(serverCfg_c.Private_keys_len))[:N:N]
	keysArray := (*[1 << 30](*C.char))(unsafe.Pointer(serverCfg_c.Private_keys))[:N:N]

	for i := 0; i < N; i++ {
		r.Keys[i] = &ServerConfigPrivateKey{
			Key: C.GoBytes(unsafe.Pointer((*C.char)(keysArray[i])), lenArray[i]),
			Tag: uint32(tagsArray[i]),
		}
	}

	return r
}
