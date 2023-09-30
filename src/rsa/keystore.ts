import IDB from "../idb.js";
import keys from "./keys.js";
import operations from "./operations.js";
import config from "../config.js";
import utils from "../utils.js";
import KeyStoreBase from "../keystore/base.js";
import {
  KeyStore,
  Config,
  KeyUse,
  CryptoSystem,
  Msg,
  PublicKey,
  PrivateKey,
} from "../types.js";

export class RSAKeyStore extends KeyStoreBase implements KeyStore {
  static async init(
    maybeCfg?: Partial<Config>,
    store?: LocalForage
  ): Promise<RSAKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.RSA,
    });

    const { storeName } = cfg;
    if (store === undefined) {
      store = IDB.createStore(storeName);
    }
    return new RSAKeyStore(cfg, store);
  }

  async createIfDoesNotExist(
    writeKeyName: string,
    exchangeKeyName: string
  ): Promise<RSAKeyStore> {
    await IDB.createIfDoesNotExist(
      exchangeKeyName,
      () =>
        keys.makeKeypair(this.cfg.rsaSize, this.cfg.hashAlg, KeyUse.Exchange),
      this.store
    );
    await IDB.createIfDoesNotExist(
      writeKeyName,
      () => keys.makeKeypair(this.cfg.rsaSize, this.cfg.hashAlg, KeyUse.Write),
      this.store
    );
    return this;
  }

  async sign(
    msg: Msg,
    writeKeyName: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const writeKey = await this.writeKey(writeKeyName);

    return utils.arrBufToBase64(
      await operations.sign(
        msg,
        writeKey.privateKey as PrivateKey,
        mergedCfg.charSize
      )
    );
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string | PublicKey,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg);

    return operations.verify(
      msg,
      sig,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.hashAlg
    );
  }

  async encrypt(
    msg: Msg,
    publicKey: string | PublicKey,
    _exchangeKeyName?: string, // unused param so that keystore interfaces match
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);

    return utils.arrBufToBase64(
      await operations.encrypt(
        msg,
        publicKey,
        mergedCfg.charSize,
        mergedCfg.hashAlg
      )
    );
  }

  async decrypt(
    cipherText: Msg,
    exchangeKeyName: string,
    publicKey?: string | PublicKey, // unused param so that keystore interfaces match
    cfg?: Partial<Config>
  ): Promise<string> {
    const exchangeKey = await this.exchangeKey(exchangeKeyName);
    const mergedCfg = config.merge(this.cfg, cfg);

    return utils.arrBufToStr(
      await operations.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey
      ),
      mergedCfg.charSize
    );
  }

  async publicExchangeKey(exchangeKeyName: string): Promise<string> {
    const exchangeKey = await this.exchangeKey(exchangeKeyName);
    return operations.getPublicKey(exchangeKey);
  }

  async publicWriteKey(writeKeyName: string): Promise<string> {
    const writeKey = await this.writeKey(writeKeyName);
    return operations.getPublicKey(writeKey);
  }
}

export default RSAKeyStore;
