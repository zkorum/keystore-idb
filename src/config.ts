import ecc from './ecc'
import {
  DEFAULT_CRYPTOSYSTEM,
  DEFAULT_ECC_CURVE,
  DEFAULT_RSA_SIZE,
  DEFAULT_SYMM_ALG,
  DEFAULT_HASH_ALG,
  DEFAULT_READ_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME
} from './constants'

export const defaultConfig = {
  type: DEFAULT_CRYPTOSYSTEM,
  curve: DEFAULT_ECC_CURVE,
  rsaSize: DEFAULT_RSA_SIZE,
  symmAlg: DEFAULT_SYMM_ALG,
  hashAlg: DEFAULT_HASH_ALG,
  readKeyName: DEFAULT_READ_KEY_NAME,
  writeKeyName: DEFAULT_WRITE_KEY_NAME
} as Config

export function normalize(
  maybeCfg?: PartialConfig,
  eccEnabled: boolean = true
): Config {
  let cfg
  if (!maybeCfg) {
    cfg = defaultConfig
  } else {
    cfg = {
      ...defaultConfig,
      ...maybeCfg
    }
  }
  if (!maybeCfg?.type) {
    cfg.type = eccEnabled ? 'ecc' : 'rsa'
  }
  return cfg
}

// Attempt a structural clone of an ECC Key (required to store in IndexedDB)
// If it throws an error, use RSA, otherwise use ECC
export async function eccEnabled(): Promise<boolean> {
  const keypair = await ecc.makeKey(DEFAULT_ECC_CURVE, KeyUse.Read)
  try {
    await structuralClone(keypair)
  } catch (err) {
    return false
  }
  return true
}

async function structuralClone(obj: any) {
  return new Promise(resolve => {
    const { port1, port2 } = new MessageChannel()
    port2.onmessage = ev => resolve(ev.data)
    port1.postMessage(obj)
  })
}

export default {
  defaultConfig,
  normalize,
  eccEnabled
}
