import ECCKeyStore from '../ecc/keystore.js'
import RSAKeyStore from '../rsa/keystore.js'
import config from '../config.js'
import IDB from '../idb.js'
import { ECCNotEnabled, checkValidCryptoSystem } from '../errors.js'
import { Config, KeyStore } from '../types.js'

export async function init(maybeCfg?: Partial<Config>): Promise<KeyStore>{
  const eccEnabled = await config.eccEnabled()
  if(!eccEnabled && maybeCfg?.type === 'ecc'){
    throw ECCNotEnabled
  }

  const cfg = config.normalize(maybeCfg, eccEnabled)

  checkValidCryptoSystem(cfg.type)

  if(cfg.type === 'ecc'){
    return ECCKeyStore.init(cfg)
  }else {
    return RSAKeyStore.init(cfg)
  }
}

export async function clear(): Promise<void> {
  return IDB.clear()
}

export default {
  init,
  clear,
}
