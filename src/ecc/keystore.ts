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
  PrivateKey,
} from "../types.js";

export class ECCKeyStore extends KeyStoreBase implements KeyStore {
  static async init(
    maybeCfg?: Partial<Config>,
    store?: LocalForage
  ): Promise<ECCKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.ECC,
    });
    const { storeName } = cfg;

    if (store === undefined) {
      store = IDB.createStore(storeName);
    }

    return new ECCKeyStore(cfg, store);
  }

  async createIfDoesNotExist(
    writeKeyName: string,
    exchangeKeyName: string
  ): Promise<ECCKeyStore> {
    await IDB.createIfDoesNotExist(
      exchangeKeyName,
      () => keys.makeKeypair(this.cfg.curve, KeyUse.Exchange),
      this.store
    );
    await IDB.createIfDoesNotExist(
      writeKeyName,
      () => keys.makeKeypair(this.cfg.curve, KeyUse.Write),
      this.store
    );
    return this;
  }

  async sign(
    msg: string,
    writeKeyName: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const writeKey = await this.writeKey(writeKeyName);

    return utils.arrBufToBase64(
      await operations.sign(
        msg,
        writeKey.privateKey as PrivateKey,
        mergedCfg.charSize,
        mergedCfg.hashAlg
      )
    );
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg);

    return operations.verify(
      msg,
      sig,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.curve,
      mergedCfg.hashAlg
    );
  }

  async encrypt(
    msg: string,
    publicKey: string,
    exchangeKeyName: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const exchangeKey = await this.exchangeKey(exchangeKeyName);

    return utils.arrBufToBase64(
      await operations.encrypt(
        msg,
        exchangeKey.privateKey as PrivateKey,
        publicKey,
        mergedCfg.charSize,
        mergedCfg.curve
      )
    );
  }

  async decrypt(
    cipherText: string,
    exchangeKeyName: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const exchangeKey = await this.exchangeKey(exchangeKeyName);

    return utils.arrBufToStr(
      await operations.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey,
        publicKey,
        mergedCfg.curve
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

export default ECCKeyStore;
